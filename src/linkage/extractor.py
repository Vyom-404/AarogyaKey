"""Extract normalized, in-memory identity evidence before any output redaction."""

from __future__ import annotations

import csv
import datetime as dt
import json
import os
import re
import unicodedata
from pathlib import Path
from typing import Any

from src.detection import PIIDetector
from src.detection.detector import field_category, is_medical_field
from src.detection.normalization import name_keys, normalize_text
from src.linkage.models import Carrier, RecordIdentity
from src.security.filesystem import read_regular_file

SUPPORTED = {".csv", ".tsv", ".json", ".txt"}
_CLINICAL_RESOURCES = {
    "organization", "practitioner", "practitionerrole", "location", "healthcareservice",
    "condition", "observation", "procedure", "medication", "medicationrequest",
    "diagnosticreport", "encounter", "servicerequest", "specimen", "careteam",
}
_PATIENT_KEYS = {"patient", "subject", "beneficiary", "patientreference", "patient_ref", "patient_reference"}
_RELATIVE_KEYS = {"relative", "guardian", "next_of_kin", "nextofkin", "emergency_contact", "father", "mother"}
_NAME_KEYS = {"name", "patient_name", "patientname", "fullname", "full_name", "given", "family",
              "first", "last", "firstname", "lastname", "middle", "local", "display"}
_GLOBAL_IDS = {"AADHAAR", "ABHA_NUMBER", "PAN", "EMAIL"}
_CARRIER_PRIORITY = {"MRN": 0, "AADHAAR": 1, "ABHA_NUMBER": 1, "PAN": 1,
                     "INSURANCE_ID": 2, "PATIENT_NAME": 3, "EMAIL": 4, "PHONE": 5}
_TITLE_OR_NICKNAME = {"ji", "sahab", "sahib", "babu", "bhai", "bhaiya", "didi", "behenji", "amma"}
_SPELLING_GROUPS = {
    "mohammad": {"mohammad", "mohammed", "muhammad", "mohd", "md"},
    "mohammed": {"mohammad", "mohammed", "muhammad", "mohd", "md"},
    "muhammad": {"mohammad", "mohammed", "muhammad", "mohd", "md"},
}


def decode_input(raw: bytes) -> str:
    if raw.startswith(b"\xef\xbb\xbf"):
        return raw[3:].decode("utf-8", errors="strict")
    if raw.startswith((b"\xff\xfe", b"\xfe\xff")):
        return raw.decode("utf-16", errors="strict")
    for encoding in ("utf-8", "cp1252"):
        try:
            return raw.decode(encoding, errors="strict")
        except UnicodeDecodeError:
            continue
    raise UnicodeError("undecodable_text")


def _norm_id(category: str, value: str) -> str:
    text = unicodedata.normalize("NFKC", value).translate(str.maketrans("०१२३४५६७८९", "0123456789"))
    text = normalize_text(text)
    if category == "PHONE":
        digits = re.sub(r"\D", "", text)
        if digits.startswith("91") and len(digits) == 12:
            digits = digits[2:]
        elif digits.startswith("0") and len(digits) == 11:
            digits = digits[1:]
        return digits if len(digits) == 10 else ""
    return re.sub(r"[^a-z0-9]", "", text)


def _name_forms(value: str) -> set[str]:
    text = normalize_text(value).replace("’", "'")
    tokens = [token for token in re.findall(r"[a-z0-9\u0900-\u097f]+", text)
              if token not in _TITLE_OR_NICKNAME]
    if not tokens:
        return set()
    groups = [_SPELLING_GROUPS.get(token, {token}) for token in tokens]
    forms: set[str] = set()
    base = " ".join(tokens)
    forms.update(name_keys(base))
    if len(tokens) >= 2:
        forms.add(" ".join((tokens[0], tokens[-1][0])))
        forms.add(" ".join((tokens[0][0], tokens[-1])))
        variants = [""]
        for index, group in enumerate(groups):
            variants = [((prefix + " ") if prefix else "") + alias for prefix in variants for alias in group]
            if len(variants) > 32:
                variants = variants[:32]
        forms.update(variants)
    return {form for form in forms if len(form) >= 2}


def _age(value: Any) -> int | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, (int, float)):
        age = int(value)
        return age if 0 <= age <= 120 and float(value).is_integer() else None
    match = re.search(r"(?<!\d)(\d{1,3})(?:\s*(?:y|yr|yrs|years?|वर्ष|साल))?\b", str(value), re.I)
    if not match:
        return None
    age = int(match.group(1))
    return age if age <= 120 else None


def _dob_values(value: Any) -> set[str]:
    if not isinstance(value, str):
        return set()
    raw = value.strip()
    candidates: set[str] = set()
    for fmt in ("%Y-%m-%d", "%Y/%m/%d", "%d/%m/%Y", "%d-%m-%Y", "%d.%m.%Y",
                "%m/%d/%Y", "%m-%d-%Y", "%d/%m/%y", "%d-%m-%y"):
        try:
            parsed = dt.datetime.strptime(raw, fmt).date()
            candidates.add(parsed.isoformat())
        except ValueError:
            continue
    # A day/month value that is ambiguous is retained as normalized evidence,
    # but it cannot be an exact DOB match against a different interpretation.
    if not candidates and re.fullmatch(r"\d{1,2}[./-]\d{1,2}[./-]\d{2,4}", raw):
        candidates.add(re.sub(r"\D", "", raw))
    return candidates


def _hospital_namespace(rel: str) -> str:
    parts = [p.casefold() for p in Path(rel).parts]
    for term in ("sanjeevani", "jeevanjyoti", "arogya", "dhhardoi", "district_hospital"):
        if any(term in part for part in parts):
            return term
    return parts[0] if parts else "unknown"


def _namespace(category: str, field: str, rel: str, value: str) -> str:
    if category in _GLOBAL_IDS:
        return "global"
    if category == "MRN":
        prefix = re.match(r"(?i)[a-z]{2,8}", value.strip())
        issuer = _hospital_namespace(rel)
        return f"mrn:{issuer}:{prefix.group(0).casefold()}" if prefix else "mrn:" + issuer
    if category == "INSURANCE_ID":
        return "insurance:" + normalize_text(field)
    return ""


def _carrier(candidate: RecordIdentity, category: str, path: tuple[str | int, ...]) -> None:
    current = candidate.carrier
    if current is None or _CARRIER_PRIORITY.get(category, 99) < _CARRIER_PRIORITY.get(current.category, 99):
        candidate.carrier = Carrier(category, path)


def _add_value(candidate: RecordIdentity, category: str, value: Any, field: str,
               rel: str, path: tuple[str | int, ...], *, patient_role: bool = True,
               carrier: bool = True) -> None:
    if value is None or isinstance(value, bool):
        return
    if isinstance(value, (dict, list)):
        return
    text = str(value).strip()
    if not text or text.casefold() in {"null", "none", "unknown", "na", "n/a", "-"}:
        return
    if category == "PATIENT_NAME":
        if not patient_role:
            return
        for form in _name_forms(text):
            candidate.add("PATIENT_NAME", form)
        if carrier:
            _carrier(candidate, category, path)
        return
    if category == "RELATIVE_NAME":
        for form in _name_forms(text):
            candidate.add("RELATIVE_NAME", form)
        return
    if category == "MRN" and sum(char.isdigit() for char in text) < 3:
        # Label-context matches can include adjacent ordinary words (for
        # example a section heading). A patient record number needs a numeric
        # core before it is admitted as linkage evidence.
        return
    if category == "AGE":
        age = _age(value)
        if age is not None:
            candidate.add("AGE", str(age))
        return
    if category == "DOB":
        for normalized in _dob_values(text):
            candidate.add("DOB", normalized)
        return
    if category in {"VILLAGE", "LOCALITY", "DISTRICT", "PIN", "ADDRESS"}:
        normalized = normalize_text(text)
        if len(normalized) > 140:
            return
        candidate.add(category, normalized)
        return
    normalized = _norm_id(category, text)
    if not normalized or len(normalized) > 100:
        return
    candidate.add(category, normalized, _namespace(category, field, rel, text))
    if carrier and category in _CARRIER_PRIORITY:
        _carrier(candidate, category, path)


def _name_role_values(node: Any, candidate: RecordIdentity, rel: str, path: tuple[str | int, ...], role: str) -> None:
    if isinstance(node, str):
        category = "PATIENT_NAME" if role == "patient" else "RELATIVE_NAME"
        _add_value(candidate, category, node, role, rel, path, patient_role=role == "patient")
    elif isinstance(node, dict):
        pieces: list[tuple[str, tuple[str | int, ...]]] = []
        for key, child in node.items():
            nkey = re.sub(r"[^a-z0-9]", "", str(key).casefold())
            if nkey in _NAME_KEYS and isinstance(child, (str, int, float)):
                pieces.append((str(child), path + (str(key),)))
            elif isinstance(child, (dict, list)):
                _name_role_values(child, candidate, rel, path + (str(key),), role)
        if len(pieces) > 1 and role == "patient":
            combined = " ".join(text for text, _ in pieces if text)
            _add_value(candidate, "PATIENT_NAME", combined, "patient_name", rel, pieces[0][1])
        for text, pth in pieces:
            _add_value(candidate, "PATIENT_NAME" if role == "patient" else "RELATIVE_NAME",
                       text, role, rel, pth, patient_role=role == "patient")
    elif isinstance(node, list):
        for index, child in enumerate(node):
            _name_role_values(child, candidate, rel, path + (index,), role)


def _walk_json(node: Any, candidate: RecordIdentity, rel: str, path: tuple[str | int, ...] = (),
               role: str = "unknown", resource_type: str = "") -> None:
    if isinstance(node, dict):
        rt = str(node.get("resourceType", resource_type)).casefold()
        if rt == "patient":
            role = "patient"
        elif rt in _CLINICAL_RESOURCES:
            role = "clinical"
        for key, child in node.items():
            key_text = str(key)
            nkey = re.sub(r"[^a-z0-9]", "", key_text.casefold())
            child_path = path + (key_text,)
            category = field_category(key_text)
            if nkey in _PATIENT_KEYS:
                if isinstance(child, str):
                    cat = field_category(key_text)
                    if cat:
                        _add_value(candidate, cat, child, key_text, rel, child_path)
                else:
                    _walk_json(child, candidate, rel, child_path, "patient", rt)
                continue
            if nkey in _RELATIVE_KEYS:
                if isinstance(child, (str, dict, list)):
                    _name_role_values(child, candidate, rel, child_path, "relative")
                continue
            if nkey == "identifier" and role == "patient":
                _walk_identifier(child, candidate, rel, child_path, key_text)
                continue
            if role == "clinical" and rt != "patient":
                if isinstance(child, (dict, list)):
                    _walk_json(child, candidate, rel, child_path, "clinical", rt)
                continue
            if nkey == "name" and role == "patient":
                _name_role_values(child, candidate, rel, child_path, "patient")
                continue
            if category in {"PATIENT_NAME", "RELATIVE_NAME"}:
                if category == "PATIENT_NAME" and (role == "patient" or nkey not in {"name", "given", "family", "first", "last"}):
                    _name_role_values(child, candidate, rel, child_path, "patient")
                elif category == "RELATIVE_NAME":
                    _name_role_values(child, candidate, rel, child_path, "relative")
                continue
            if category and not is_medical_field(key_text):
                if nkey in {"age", "patientage", "umar", "years"}:
                    _add_value(candidate, "AGE", child, key_text, rel, child_path, patient_role=role == "patient")
                elif isinstance(child, (str, int, float)):
                    _add_value(candidate, category, child, key_text, rel, child_path,
                               patient_role=role != "clinical")
                elif category in {"MRN", "AADHAAR", "ABHA_NUMBER", "PAN", "PHONE", "EMAIL", "INSURANCE_ID"}:
                    _walk_identifier(child, candidate, rel, child_path, key_text)
                continue
            if nkey in {"age", "patientage", "umar", "years"}:
                _add_value(candidate, "AGE", child, key_text, rel, child_path, patient_role=role != "clinical")
            elif nkey in {"dob", "birthdate", "dateofbirth", "janmtithi"}:
                _add_value(candidate, "DOB", child, key_text, rel, child_path, patient_role=role != "clinical")
            elif nkey in {"village", "gaon", "gram", "city", "town", "district", "jila", "pin", "pincode", "postalcode"}:
                loc_category = "VILLAGE" if nkey in {"village", "gaon", "gram"} else "PIN" if "pin" in nkey or "postal" in nkey else "DISTRICT" if nkey in {"district", "jila"} else "LOCALITY"
                _add_value(candidate, loc_category, child, key_text, rel, child_path, patient_role=role != "clinical")
            elif isinstance(child, (dict, list)):
                _walk_json(child, candidate, rel, child_path, role, rt)
    elif isinstance(node, list):
        for index, child in enumerate(node):
            _walk_json(child, candidate, rel, path + (index,), role, resource_type)


def _walk_identifier(node: Any, candidate: RecordIdentity, rel: str, path: tuple[str | int, ...], field: str) -> None:
    items = node if isinstance(node, list) else [node]
    for index, item in enumerate(items):
        if not isinstance(item, dict):
            continue
        context = " ".join(str(item.get(k, "")) for k in ("system", "type", "value"))
        # FHIR type coding commonly says MR or Medical record number.
        def gather(value: Any, value_path: tuple[str | int, ...], parent: str = "") -> None:
            if isinstance(value, dict):
                for k, v in value.items():
                    gather(v, value_path + (str(k),), str(k))
            elif isinstance(value, list):
                for i, v in enumerate(value):
                    gather(v, value_path + (i,), parent)
            elif parent == "value" or (not isinstance(value, (dict, list)) and field == "patient_id"):
                value_text = str(value)
                cat = field_category(context) or field_category(field) or "MRN"
                _add_value(candidate, cat, value_text, context or field, rel, value_path)
        gather(item, path + (index,))


def _make_candidate(rel: str, loc: str, file_format: str) -> RecordIdentity:
    return RecordIdentity(rel, loc, file_format)


def extract_file_records(path: Path, rel: str, detector: PIIDetector,
                         max_bytes: int = 50 * 1024 * 1024) -> list[RecordIdentity]:
    """Build per-output-locator identity evidence from a supported file."""
    if path.is_symlink() or path.suffix.lower() not in SUPPORTED:
        return []
    try:
        text = decode_input(read_regular_file(path, max_bytes))
        suffix = path.suffix.lower()
        if suffix in {".csv", ".tsv"}:
            rows = list(csv.reader(text.splitlines(), delimiter="\t" if suffix == ".tsv" else ",", strict=True))
            if not rows:
                return []
            headers = rows[0]
            result = []
            for row_index, row in enumerate(rows[1:]):
                candidate = _make_candidate(rel, f"row:{row_index}", suffix[1:])
                first: tuple[str, tuple[str | int, ...]] | None = None
                last: tuple[str, tuple[str | int, ...]] | None = None
                for col, value in enumerate(row):
                    if col >= len(headers):
                        continue
                    header = headers[col]
                    category = field_category(header)
                    nheader = re.sub(r"[^a-z0-9]", "", header.casefold())
                    field_path: tuple[str | int, ...] = (col,)
                    if nheader in {"age", "umar", "patientage", "ageyears"}:
                        _add_value(candidate, "AGE", value, header, rel, field_path)
                    elif nheader in {"dob", "dateofbirth", "birthdate", "janmtithi"} or category == "DOB":
                        _add_value(candidate, "DOB", value, header, rel, field_path)
                    elif nheader in {"first", "firstname", "givenname"}:
                        first = (value, field_path)
                    elif nheader in {"last", "lastname", "surname", "familyname"}:
                        last = (value, field_path)
                    elif category:
                        _add_value(candidate, category, value, header, rel, field_path,
                                   patient_role=category != "RELATIVE_NAME")
                    elif nheader in {"village", "gaon", "gram", "village_mohalla"}:
                        _add_value(candidate, "VILLAGE", value, header, rel, field_path)
                    elif nheader in {"city", "town", "district", "jila", "jilha"}:
                        cat = "DISTRICT" if nheader in {"district", "jila", "jilha"} else "LOCALITY"
                        _add_value(candidate, cat, value, header, rel, field_path)
                if first and last:
                    _add_value(candidate, "PATIENT_NAME", first[0] + " " + last[0], "patient_name", rel, first[1])
                result.append(candidate)
            return result
        if suffix == ".json":
            data = json.loads(text)
            if isinstance(data, dict) and data.get("resourceType") == "Bundle":
                candidate = _make_candidate(rel, "doc", "fhir")
                _walk_json(data, candidate, rel)
                return [candidate]
            records: list[RecordIdentity] = []
            if isinstance(data, dict):
                for key, items in data.items():
                    if isinstance(items, list) and items and all(isinstance(item, dict) for item in items):
                        escaped = str(key).replace("~", "~0").replace("/", "~1")
                        for index, item in enumerate(items):
                            candidate = _make_candidate(rel, f"/{escaped}/{index}", "json")
                            role = "patient" if "patient" in str(key).casefold() else "unknown"
                            _walk_json(item, candidate, rel, (key, index), role)
                            records.append(candidate)
            if not records:
                candidate = _make_candidate(rel, "doc", "json")
                _walk_json(data, candidate, rel)
                records.append(candidate)
            return records
        candidate = _make_candidate(rel, "doc", "text")
        for hit in detector.find(text):
            if hit.category == "PATIENT_NAME" and hit.method not in {
                "identity_label", "hindi_patient_object_context", "name_before_relation",
                "name_report_of", "name_honorific", "honorific_name", "name_age_context",
            }:
                continue
            if hit.category == "RELATIVE_NAME" and hit.method not in {
                "relationship_context", "kinship_suffix_context", "person_role_context",
            }:
                continue
            value = text[hit.start:hit.end]
            if hit.category in {"PATIENT_NAME", "RELATIVE_NAME"}:
                for form in _name_forms(value):
                    candidate.add(hit.category, form)
                if hit.category == "PATIENT_NAME":
                    candidate.patient_name_spans.append((hit.start, hit.end))
                    if candidate.carrier is None or _CARRIER_PRIORITY["PATIENT_NAME"] < _CARRIER_PRIORITY.get(candidate.carrier.category, 99):
                        candidate.carrier = Carrier("PATIENT_NAME", ())
            elif hit.category in _CARRIER_PRIORITY or hit.category == "DOB":
                _add_value(candidate, hit.category, value, hit.category, rel, ())
            elif hit.category in {"VILLAGE", "LOCALITY", "ADDRESS"}:
                _add_value(candidate, hit.category, value, hit.category, rel, ())
        for match in re.finditer(r"(?i)\b(?:age|umar|वय|आयु|उम्र)\s*[:=]?\s*(\d{1,3})\b", text):
            _add_value(candidate, "AGE", match.group(1), "age", rel, ())
        return [candidate]
    except (OSError, UnicodeError, ValueError, csv.Error, RecursionError):
        return []


def extract_records(input_dir: Path, detector: PIIDetector, max_bytes: int = 50 * 1024 * 1024) -> list[RecordIdentity]:
    records: list[RecordIdentity] = []
    for current, dirs, names in os.walk(input_dir, followlinks=False):
        base = Path(current)
        dirs[:] = sorted(d for d in dirs if not (base / d).is_symlink())
        for name in sorted(names):
            path = base / name
            try:
                if path.is_symlink() or path.stat().st_size > max_bytes:
                    continue
                rel = path.relative_to(input_dir).as_posix()
                records.extend(extract_file_records(path, rel, detector, max_bytes))
            except OSError:
                continue
    return sorted(records, key=lambda item: (item.file, item.loc))
