"""Blocking, explainable pair scoring, conservative clustering and HMAC IDs."""

from __future__ import annotations

import itertools
import re
from collections import defaultdict
from difflib import SequenceMatcher

from src.detection.normalization import normalize_text
from src.linkage.models import IdentitySignal, LinkDecision, LinkResult, RecordIdentity
from src.linkage.pseudonymizer import Pseudonymizer

# AADHAAR here means a complete validated 12-digit value; masked suffixes are
# deliberately kept out of this global, unique-identifier set.
_GLOBAL_STRONG = {"AADHAAR", "ABHA_NUMBER", "PAN", "EMAIL"}
_LOCAL_STRONG = {"MRN", "INSURANCE_ID"}
_ALL_STRONG = _GLOBAL_STRONG | _LOCAL_STRONG


def _bucket(record: RecordIdentity, category: str) -> set[str]:
    return {s.value for s in record.signals if s.category == category}


def _scoped(record: RecordIdentity, category: str) -> set[tuple[str, str]]:
    return {(s.namespace, s.value) for s in record.signals if s.category == category}


def _name_similarity(left: RecordIdentity, right: RecordIdentity) -> tuple[float, bool]:
    a, b = _bucket(left, "PATIENT_NAME"), _bucket(right, "PATIENT_NAME")
    if not a or not b:
        return 0.0, False
    if a.intersection(b):
        return 1.0, True
    best = 0.0
    for x in a:
        for y in b:
            if min(len(x), len(y)) < 6:
                continue
            ratio = SequenceMatcher(None, x, y, autojunk=False).ratio()
            if ratio > best:
                best = ratio
    return best, False


def _soundex(value: str) -> str:
    token = re.sub(r"[^a-z]", "", normalize_text(value).split()[0] if value else "")
    if not token:
        return ""
    codes = {**dict.fromkeys("bfpv", "1"), **dict.fromkeys("cgjkqsxz", "2"),
             **dict.fromkeys("dt", "3"), "l": "4", **dict.fromkeys("mn", "5"), "r": "6"}
    output = [token[0].upper()]
    previous = codes.get(token[0], "")
    for char in token[1:]:
        code = codes.get(char, "")
        if code and code != previous:
            output.append(code)
        previous = code
    return ("".join(output) + "000")[:4]


class PatientResolver:
    """High-precision resolver; weak names and demographics only create candidates."""

    def __init__(self, minimum_confidence: float = 0.92, maximum_block_size: int = 256) -> None:
        self.minimum_confidence = minimum_confidence
        self.maximum_block_size = maximum_block_size
        self._ambiguous_name_relative: set[tuple[str, str]] = set()

    def _find_ambiguous_name_relative(self, records: list[RecordIdentity]) -> set[tuple[str, str]]:
        observations: dict[tuple[str, str], tuple[set[str], set[str]]] = {}
        for record in records:
            for name in _bucket(record, "PATIENT_NAME"):
                for relative in _bucket(record, "RELATIVE_NAME"):
                    ages, dobs = observations.setdefault((name, relative), (set(), set()))
                    ages.update(_bucket(record, "AGE"))
                    dobs.update(_bucket(record, "DOB"))
        ambiguous: set[tuple[str, str]] = set()
        for key, (ages, dobs) in observations.items():
            if len(dobs) > 1:
                ambiguous.add(key)
            elif len(ages) > 1:
                try:
                    if max(map(int, ages)) - min(map(int, ages)) > 1:
                        ambiguous.add(key)
                except ValueError:
                    ambiguous.add(key)
        return ambiguous

    def _candidate_pairs(self, records: list[RecordIdentity]) -> set[tuple[int, int]]:
        blocks: dict[tuple[str, str, str], set[int]] = defaultdict(set)
        for index, record in enumerate(records):
            for signal in record.signals:
                if signal.category in _ALL_STRONG | {"PHONE", "DOB", "RELATIVE_NAME", "VILLAGE"}:
                    if signal.value:
                        scope = signal.namespace if signal.category in _LOCAL_STRONG else ""
                        blocks[(signal.category, scope, signal.value)].add(index)
                elif signal.category == "PATIENT_NAME":
                    words = signal.value.split()
                    if len(words) >= 2:
                        blocks[("PATIENT_NAME", "", signal.value)].add(index)
                        for word in words:
                            if len(word) >= 5:
                                blocks[("NAME_PHONETIC", "", _soundex(word))].add(index)
        pairs: set[tuple[int, int]] = set()
        for members in blocks.values():
            ordered = sorted(members)
            if len(ordered) < 2 or len(ordered) > self.maximum_block_size:
                continue
            pairs.update(itertools.combinations(ordered, 2))
        return pairs

    def _hard_conflict(self, left: RecordIdentity, right: RecordIdentity, name_score: float) -> tuple[str, ...]:
        conflicts: list[str] = []
        for category in _ALL_STRONG:
            a, b = _scoped(left, category), _scoped(right, category)
            if not a or not b or a.intersection(b):
                continue
            # Different hospital-local MRNs are expected across systems.
            if category == "MRN":
                shared_scopes = {scope for scope, _ in a} & {scope for scope, _ in b}
                if shared_scopes:
                    conflicts.append("conflicting_same_scope_mrn")
            elif category == "INSURANCE_ID":
                shared_scopes = {scope for scope, _ in a} & {scope for scope, _ in b}
                if shared_scopes:
                    conflicts.append("conflicting_same_scheme_insurance_id")
            else:
                conflicts.append("conflicting_global_identifier")
        dob_a, dob_b = _bucket(left, "DOB"), _bucket(right, "DOB")
        if dob_a and dob_b and not dob_a.intersection(dob_b):
            conflicts.append("conflicting_dob")
        age_a, age_b = _bucket(left, "AGE"), _bucket(right, "AGE")
        if age_a and age_b and not dob_a.intersection(dob_b):
            try:
                if min(abs(int(a) - int(b)) for a in age_a for b in age_b) > 5:
                    conflicts.append("large_age_disagreement")
            except ValueError:
                pass
        names_a, names_b = _bucket(left, "PATIENT_NAME"), _bucket(right, "PATIENT_NAME")
        if names_a and names_b and name_score < 0.45:
            # An exact reliable identifier can tolerate a changed name only when
            # DOB agrees. It cannot reconcile unrelated names and DOBs.
            exact_global = any(_scoped(left, cat).intersection(_scoped(right, cat)) for cat in _GLOBAL_STRONG)
            if not exact_global or (dob_a and dob_b and not dob_a.intersection(dob_b)):
                conflicts.append("incompatible_patient_names")
        relatives_a, relatives_b = _bucket(left, "RELATIVE_NAME"), _bucket(right, "RELATIVE_NAME")
        villages_a, villages_b = _bucket(left, "VILLAGE"), _bucket(right, "VILLAGE")
        phones_a, phones_b = _bucket(left, "PHONE"), _bucket(right, "PHONE")
        exact_global = any(_scoped(left, cat).intersection(_scoped(right, cat)) for cat in _GLOBAL_STRONG)
        shared_relative_signatures = {
            (name, relative) for name in names_a.intersection(names_b)
            for relative in relatives_a.intersection(relatives_b)
        }
        if shared_relative_signatures.intersection(self._ambiguous_name_relative) and not exact_global:
            conflicts.append("non_unique_name_relative_signature")
        if (names_a.intersection(names_b) and relatives_a.intersection(relatives_b)
                and phones_a and phones_b and not phones_a.intersection(phones_b)
                and not exact_global):
            conflicts.append("conflicting_phone_with_name_relative")
        if (names_a and names_b and name_score == 1.0 and relatives_a and relatives_b
                and not relatives_a.intersection(relatives_b) and villages_a and villages_b
                and not villages_a.intersection(villages_b) and not exact_global):
            conflicts.append("homonym_support_conflict")
        return tuple(dict.fromkeys(conflicts))

    def _score(self, left: RecordIdentity, right: RecordIdentity) -> LinkDecision:
        left_ref, right_ref = (left.file, left.loc), (right.file, right.loc)
        name_score, same_name = _name_similarity(left, right)
        conflicts = self._hard_conflict(left, right, name_score)
        if conflicts:
            return LinkDecision(left_ref, right_ref, "no_match", 0.0, conflicts)

        evidence: list[str] = []
        confidence = 0.0
        shared_global = [cat for cat in _GLOBAL_STRONG
                         if _scoped(left, cat).intersection(_scoped(right, cat))]
        shared_local = [cat for cat in _LOCAL_STRONG
                        if _scoped(left, cat).intersection(_scoped(right, cat))]
        same_scoped_mrn = bool(_scoped(left, "MRN").intersection(_scoped(right, "MRN")))
        shared_phone = bool(_bucket(left, "PHONE").intersection(_bucket(right, "PHONE")))
        same_dob = bool(_bucket(left, "DOB").intersection(_bucket(right, "DOB")))
        same_relative = bool(_bucket(left, "RELATIVE_NAME").intersection(_bucket(right, "RELATIVE_NAME")))
        same_village = bool(_bucket(left, "VILLAGE").intersection(_bucket(right, "VILLAGE")))
        age_close = False
        if _bucket(left, "AGE") and _bucket(right, "AGE"):
            try:
                age_close = min(abs(int(a) - int(b)) for a in _bucket(left, "AGE") for b in _bucket(right, "AGE")) <= 1
            except ValueError:
                pass

        if shared_global:
            evidence.extend("exact_" + category.casefold() for category in sorted(shared_global))
            confidence = 0.995
        elif same_scoped_mrn:
            # An exact MRN within the same inferred hospital namespace is a
            # strong identifier by itself. Contradictory DOB/global IDs and
            # incompatible names have already been rejected above.
            evidence.append("exact_hospital_scoped_mrn")
            if shared_phone:
                evidence.append("shared_phone")
            confidence = 0.985 if shared_phone else 0.97
        elif shared_local and (same_name or same_dob):
            evidence.extend("exact_" + category.casefold() for category in sorted(shared_local))
            confidence = 0.985
        elif same_name and same_dob:
            evidence.extend(("normalized_name", "exact_dob"))
            confidence = 0.975
        elif same_name and same_relative:
            evidence.extend(("normalized_name", "exact_relative_name"))
            confidence = 0.955
        elif same_name and shared_phone:
            evidence.extend(("normalized_name", "shared_phone"))
            confidence = 0.925
        elif name_score >= 0.88 and shared_phone and (same_dob or same_relative):
            evidence.extend(("fuzzy_or_transliterated_name", "shared_phone"))
            if same_dob:
                evidence.append("exact_dob")
            if same_relative:
                evidence.append("exact_relative_name")
            confidence = 0.94
        elif name_score >= 0.88 and (same_dob or same_relative) and same_village and age_close:
            evidence.append("fuzzy_or_transliterated_name")
            if same_dob:
                evidence.append("exact_dob")
            if same_relative:
                evidence.append("exact_relative_name")
            evidence.extend(("same_village", "age_within_one_year"))
            confidence = 0.93

        state = "match" if confidence >= self.minimum_confidence else "ambiguous"
        if not evidence:
            evidence.append("insufficient_independent_evidence")
        return LinkDecision(left_ref, right_ref, state, confidence, tuple(evidence))

    def resolve(self, records: list[RecordIdentity], pseudonymizer: Pseudonymizer) -> LinkResult:
        records = sorted(records, key=lambda r: (r.file, r.loc))
        self._ambiguous_name_relative = self._find_ambiguous_name_relative(records)
        pair_decisions: list[LinkDecision] = []
        for left_index, right_index in sorted(self._candidate_pairs(records)):
            pair_decisions.append(self._score(records[left_index], records[right_index]))

        parent = list(range(len(records)))

        def find(index: int) -> int:
            while parent[index] != index:
                parent[index] = parent[parent[index]]
                index = parent[index]
            return index

        accepted = sorted((d for d in pair_decisions if d.state == "match"),
                          key=lambda d: (-d.confidence, d.left, d.right))
        decisions = list(d for d in pair_decisions if d.state != "match")
        index_by_ref = {(record.file, record.loc): i for i, record in enumerate(records)}
        for decision in accepted:
            left_root, right_root = find(index_by_ref[decision.left]), find(index_by_ref[decision.right])
            if left_root == right_root:
                decisions.append(decision)
                continue
            left_members = [i for i in range(len(records)) if find(i) == left_root]
            right_members = [i for i in range(len(records)) if find(i) == right_root]
            compatible = True
            for i in left_members:
                for j in right_members:
                    name_score, _ = _name_similarity(records[i], records[j])
                    if self._hard_conflict(records[i], records[j], name_score):
                        compatible = False
                        break
                if not compatible:
                    break
            if compatible:
                parent[max(left_root, right_root)] = min(left_root, right_root)
                decisions.append(decision)
            else:
                decisions.append(LinkDecision(decision.left, decision.right, "ambiguous", 0.0,
                                              decision.evidence + ("cluster_consistency_rejected",)))

        clusters: dict[int, list[int]] = defaultdict(list)
        for i in range(len(records)):
            clusters[find(i)].append(i)
        cluster_anchors: dict[int, tuple[str, ...]] = {}
        for root, members in clusters.items():
            anchor = self._cluster_anchor([records[i] for i in members])
            if anchor:
                cluster_anchors[root] = anchor

        # Identical evidence with no disambiguating identity must stay unresolved
        # rather than receive the same pseudonym in separate homonym clusters.
        anchor_roots: dict[tuple[str, ...], list[int]] = defaultdict(list)
        for root, anchor in cluster_anchors.items():
            anchor_roots[anchor].append(root)
        blocked_roots = {root for roots in anchor_roots.values() if len(roots) > 1 for root in roots}
        pseudonyms: dict[tuple[str, str], str] = {}
        for root, members in clusters.items():
            anchor = cluster_anchors.get(root)
            if not anchor or root in blocked_roots:
                continue
            pseudonym = pseudonymizer.pseudonym(anchor)
            for index in members:
                ref = (records[index].file, records[index].loc)
                pseudonyms[ref] = pseudonym
        linked_count = len(pseudonyms)
        unresolved = max(0, len(records) - linked_count)
        return LinkResult(records, pseudonyms, sorted(decisions, key=lambda d: (d.left, d.right)),
                          linked_count, unresolved)

    @staticmethod
    def _cluster_anchor(cluster: list[RecordIdentity]) -> tuple[str, ...] | None:
        shared_values: set[tuple[str, str, str]] | None = None
        for record in cluster:
            local = {(s.category, s.namespace, s.value) for s in record.signals if s.category in _ALL_STRONG}
            shared_values = local if shared_values is None else shared_values.intersection(local)
        if shared_values:
            strongest = sorted(shared_values, key=lambda item: (
                0 if item[0] in _GLOBAL_STRONG else 1, item[0], item[1], item[2]
            ))[0]
            return ("reliable-id", *strongest)

        # For cross-hospital clusters, site-local MRNs differ by design. A
        # shared name plus DOB is a more stable anchor than the union of those
        # local IDs, and remains unchanged as records are added.
        common_names = set.intersection(*(_bucket(record, "PATIENT_NAME") for record in cluster)) if cluster else set()
        common_dobs = set.intersection(*(_bucket(record, "DOB") for record in cluster)) if cluster else set()
        if common_names and common_dobs:
            return ("resolved-identity", sorted(common_names)[0], "dob=" + sorted(common_dobs)[0])
        common_relatives = set.intersection(*(_bucket(record, "RELATIVE_NAME") for record in cluster)) if cluster else set()
        if common_names and common_relatives:
            return ("resolved-identity", sorted(common_names)[0], "relative=" + sorted(common_relatives)[0])
        common_villages = set.intersection(*(_bucket(record, "VILLAGE") for record in cluster)) if cluster else set()
        common_ages = set.intersection(*(_bucket(record, "AGE") for record in cluster)) if cluster else set()
        all_strong = sorted({(s.category, s.namespace, s.value) for record in cluster
                             for s in record.signals if s.category in _ALL_STRONG})
        if all_strong:
            # Adding another linked record must not change an existing patient's
            # pseudonym merely because it contributes another hospital ID.
            strongest = sorted(all_strong, key=lambda item: (
                0 if item[0] in _GLOBAL_STRONG else 1, item[0], item[1], item[2]
            ))[0]
            return ("reliable-id", *strongest)

        names = sorted(common_names or set().union(*(_bucket(r, "PATIENT_NAME") for r in cluster)))
        dobs = sorted(set().union(*(_bucket(r, "DOB") for r in cluster)))
        relatives = sorted(set().union(*(_bucket(r, "RELATIVE_NAME") for r in cluster)))
        villages = sorted(set().union(*(_bucket(r, "VILLAGE") for r in cluster)))
        phones = sorted(set().union(*(_bucket(r, "PHONE") for r in cluster)))
        ages = sorted(set().union(*(_bucket(r, "AGE") for r in cluster)))
        # Without a usable name, no stable patient-scoped identity is available.
        if not names:
            return None
        # Demographics such as name, age, and village are not unique enough to
        # create a patient token for an unresolved singleton. In particular,
        # two same-name residents with the same age/location must not converge
        # on the same pseudonym merely because their weak profile matches.
        if len(cluster) == 1 and not (dobs or relatives or phones):
            return None
        return ("resolved-identity", names[0], *("dob=" + value for value in dobs[:1]),
                *("relative=" + value for value in relatives[:1]),
                *("village=" + value for value in villages[:1]),
                *("phone=" + value for value in phones[:1]),
                *("age=" + value for value in ages[:1]))
