#!/usr/bin/env python3
"""Generate an independent, deterministic synthetic adversarial corpus.

No organizer truth/canaries are read. Raw generated records and outputs are kept
under a temporary directory and deleted when the command exits. The JSON summary
contains aggregate metrics and category counts only.
"""

from __future__ import annotations

import argparse
import base64
import csv
import datetime as dt
import json
import random
import os
import re
import sys
import tempfile
import unicodedata
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from src.linkage import PatientResolver, Pseudonymizer, RecordIdentity  # noqa: E402
from src.privacy import collect_privacy_records  # noqa: E402
from src.privacy.risk import _tuple  # noqa: E402

GIVEN = ("Naveen", "Ishita", "Ronav", "Kritika", "Aviraj", "Tanvi", "Reyansh", "Vamika")
FAMILY = ("Bendre", "Khatri", "Soman", "Dandekar", "Bajpai", "Kamble", "Chitnis", "Sirohi")
HINDI_GIVEN = ("नवीन", "इशिता", "रोनव", "कृतिका", "अविराज", "तन्वी", "रेयांश", "वामिका")
HINDI_FAMILY = ("बेंद्रे", "खत्री", "सोमन", "दांडेकर", "बाजपेयी", "कांबले", "चितनिस", "सिरोही")
CLINICAL = (
    "Dolo 650 BD x 5 days", "1-0-1", "BP 121/79 mmHg", "HbA1c 6.8%",
    "Metformin 500 mg", "Dengue", "Appendectomy", "SpO2 97%",
    "Serum sodium 138 mmol/L", "Temperature 38.2°C", "K/C/O diabetes",
)


def generated_name(rng: random.Random, index: int) -> tuple[str, str]:
    slot = index % len(GIVEN)
    round_no = index // len(GIVEN)
    suffix = chr(ord("A") + round_no)
    return f"{GIVEN[slot]}{suffix} {FAMILY[(slot + round_no) % len(FAMILY)]}", \
        f"{HINDI_GIVEN[slot]}{suffix} {HINDI_FAMILY[(slot + round_no) % len(HINDI_FAMILY)]}"


def _write(path: Path, content: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(content.encode("utf-8") if isinstance(content, str) else content)


def generate_corpus(root: Path, seed: int, oversized_limit: int = 1_000_000,
                    vary_profiles: bool = False) -> dict[str, Any]:
    """Create files plus an in-memory truth manifest; the manifest is never saved."""
    rng = random.Random(seed)
    source = root / "input"
    source.mkdir(parents=True)
    identities: list[dict[str, str]] = []
    clinicians: list[str] = []
    qi_profiles: list[dict[str, Any]] = []
    csv_rows = ["patient_name,mrn,phone,aadhaar,abha,pan,insurance_id,age,village,district,pin,diagnosis,medicine,dose"]
    json_records: list[dict[str, Any]] = []
    notes: list[str] = []
    profile_offset = rng.randrange(8 * 8) if vary_profiles else 0
    village_roots = ("Basantpur", "Devnagar", "Haripura", "Keshavgram", "Madhopur", "Nandgaon")
    district_names = ("Shivgarh", "Ratanpur", "Malvan", "Suryanagar")
    diagnosis_names = ("Dengue", "Asthma", "Type 2 diabetes", "Migraine", "Pneumonia", "Anemia")
    timeline_start = dt.date(2021 + seed % 4, 1, 1) + dt.timedelta(days=seed % 280)
    for index in range(16):
        name_index = index + profile_offset
        latin, devanagari = generated_name(rng, name_index)
        relative, _ = generated_name(rng, name_index + 37)
        numeric = rng.randrange(10**9, 10**10)
        phone = f"+91 {numeric // 10**7:03d} {numeric // 10**4 % 1000:03d} {numeric % 10000:04d}"
        aadhaar = f"{rng.randrange(10**11, 10**12)}"
        abha = f"{rng.randrange(10**13, 10**14)}"
        pan = f"{''.join(rng.choice('ABCDEFGHJKLMNPQRSTUVWXYZ') for _ in range(5))}{rng.randrange(1000,10000)}{rng.choice('ABCDEFGHJKLMNPQRSTUVWXYZ')}"
        mrn = f"QX-{seed % 1000:03d}-{index:04d}"
        policy_id = f"INS-{seed % 1000:03d}-{index:04d}-ZX"
        village = (f"{village_roots[(index + seed) % len(village_roots)]}{index:02d}"
                   if vary_profiles else f"Kiranpur{index:02d}")
        district = district_names[(index + seed // 7) % len(district_names)] if vary_profiles else "Nandipur"
        hospital = f"Facility-{(index + seed) % 5}" if vary_profiles else f"Facility-{index % 3}"
        diagnosis = (diagnosis_names[(index + seed // 11) % len(diagnosis_names)]
                     if vary_profiles else ("Dengue" if index % 4 else "Asthma"))
        age = (18 + ((index * 7 + seed) % 73)) if vary_profiles else 21 + index
        admission = timeline_start + dt.timedelta(days=index * 29)
        clinician, _ = generated_name(rng, name_index + 71)
        clinicians.append(clinician)
        phone_digits = re.sub(r"\D", "", phone)
        identities.append({"name": latin, "deva": devanagari, "relative": relative, "phone": phone,
                           "aadhaar": aadhaar, "abha": abha, "pan": pan, "mrn": mrn,
                           "insurance": policy_id, "patient_key": f"PT-{seed}-{index}"})
        csv_rows.append(",".join((latin, mrn, phone, aadhaar, abha, pan, policy_id,
                                  str(age), village, district, f"{(41 + seed % 40):02d}{index:04d}",
                                  diagnosis, "Metformin 500 mg", "1-0-1", latin)))
        profile = {"patient_key": f"PT-{seed}-{index}", "age": age, "village": village,
                   "district": district, "pin": f"{(41 + seed % 40):02d}{index:04d}", "hospital": hospital,
                   "admission_date": admission.isoformat() if vary_profiles else f"2026-{(index % 9) + 1:02d}-{(index % 20) + 1:02d}",
                   "diagnosis": diagnosis, "stay_duration": "3 days"}
        qi_profiles.append(profile)
        json_records.append({
            "patient": {"name": {"text": devanagari}, "identifier": [{"type": {"text": "Medical record number"}, "value": mrn}]},
            "identifiers": {"abha_number": abha, "insurance_id": policy_id, "pan": pan},
            "metadata": {"source_path": f"/intake/{latin.replace(' ', '_')}/{phone_digits}/export"},
            "age": age, "village": village, "district": district, "pin": f"{(41 + seed % 40):02d}{index:04d}",
            "hospital": hospital, "admission_date": admission.isoformat() if vary_profiles else f"2026-{(index % 9) + 1:02d}-{(index % 20) + 1:02d}",
            "discharge_date": (admission + dt.timedelta(days=3)).isoformat() if vary_profiles else f"2026-{(index % 9) + 1:02d}-{(index % 20) + 4:02d}",
            "visits": [
                {"visit_date": admission.isoformat() if vary_profiles else f"2026-{(index % 9) + 1:02d}-{(index % 20) + 1:02d}", "diagnosis": diagnosis,
                 "stay_duration": "3 days"},
                {"visit_date": (admission + dt.timedelta(days=20)).isoformat() if vary_profiles else f"2026-{(index % 9) + 1:02d}-{(index % 20) + 21:02d}", "diagnosis": diagnosis,
                 "stay_duration": "2 days"},
            ],
            "stay_duration": "3 days", "diagnosis": diagnosis,
            "medicine": "Metformin 500 mg", "dose": "1-0-1",
            f"opaque_{latin.replace(' ', '_')}": f"header-key synthetic value {mrn}",
        })
        clinical = CLINICAL[index % len(CLINICAL)]
        odd_name = latin.replace(" ", "\u00a0") if index % 2 else latin.replace(" ", "\u200b")
        attachment = base64.b64encode(f"patient {latin}; phone {phone}; id {mrn}".encode()).decode()
        notes.append(f"Patient Name: {odd_name}\nS/o: {relative}\nC/O: {relative}\nD/o: {relative}\nW/o: {relative}\n"
                     f"Phone: {phone}\nMRN: {mrn}\n"
                     f"ABHA: {abha}\nAadhaar: {aadhaar}\nInsurance ID: {policy_id}\n"
                     f"Dr. {clinician} reviewed; {clinical}.\n"
                     f"{devanagari} को आज जांचा गया; C/O fever; K/C/O diabetes.\n"
                     f"Opaque attachment: {attachment}\n")

    # Do not reuse organizer labels or patient values: generated aliases are new.
    csv_rows[0] += f",Patient Name {identities[0]['name']}"
    _write(source / f"intake/{identities[0]['name'].replace(' ', '_')}_{identities[0]['phone'].replace(' ', '')}.txt",
           notes[0])
    _write(source / "tables/claims.csv", "\n".join(csv_rows) + "\n")
    _write(source / "records/nested.json", json.dumps({"records": json_records}, ensure_ascii=False))
    _write(source / "notes/multilingual.txt", "".join(notes[1:]))

    # A FHIR-shaped bundle probes Patient, Practitioner, metadata, narrative,
    # identifier and clinical values without relying on the official fixtures.
    patient = identities[2]
    fhir_clinician = clinicians[2]
    bundle = {"resourceType": "Bundle", "id": "bundle-synthetic", "type": "collection", "entry": [
        {"fullUrl": "urn:uuid:patient-1", "resource": {"resourceType": "Patient", "id": "patient-1",
         "identifier": [{"type": {"text": "MRN"}, "value": patient["mrn"]}],
         "name": [{"text": patient["name"]}], "telecom": [{"system": "phone", "value": patient["phone"]}],
         "address": [{"city": "Kiranpur02", "postalCode": "410002"}]}},
        {"fullUrl": "urn:uuid:practitioner-1", "resource": {"resourceType": "Practitioner", "id": "doctor-1",
         "name": [{"text": f"Dr. {fhir_clinician}"}]}},
        {"resource": {"resourceType": "Observation", "status": "final", "code": {"text": "Blood pressure"},
         "subject": {"reference": "urn:uuid:patient-1"}, "valueQuantity": {"value": 121, "unit": "mmHg"}}},
    ]}
    _write(source / "fhir/new_bundle.json", json.dumps(bundle, ensure_ascii=False))

    # Robustness cases must be quarantined, never copied as sanitized raw bytes.
    _write(source / "broken/truncated.json", b'{"records": [{"patient_name": "synthetic dangling')
    _write(source / "broken/invalid_encoding.txt", b"Patient Name: Synthetic\xff\xfe")
    _write(source / "broken/malformed_fhir.json", '{"resourceType":"Bundle","type":7,"entry":[]}')
    _write(source / "unsupported/notes.xml", "<note>Patient Name: Synthetic</note>")
    _write(source / "broken/deep.json", "{" + '"x":' * 105 + '"leaf"' + "}" * 105)
    _write(source / "broken/too_large.txt", b"X" * (oversized_limit + 1))
    external = root / "external.txt"
    _write(external, "Synthetic symlink target; never export")
    try:
        (source / "broken/symlink.txt").symlink_to(external)
    except (OSError, NotImplementedError):
        pass

    import hashlib
    input_hashes = {path.relative_to(source).as_posix(): hashlib.sha256(path.read_bytes()).hexdigest()
                    for path in source.rglob("*") if path.is_file() and not path.is_symlink()}
    return {"source": source, "identities": identities, "clinical": list(CLINICAL),
            "clinicians": clinicians,
            "seed": seed, "max_file_bytes": oversized_limit, "input_hashes": input_hashes,
            "qi_profiles": qi_profiles}


def pair_metrics(records: list[RecordIdentity], truth: dict[tuple[str, str], str], result: Any) -> dict[str, float | int]:
    refs = [(item.file, item.loc) for item in records]
    tp = fp = fn = 0
    for i, left in enumerate(refs):
        for right in refs[i + 1:]:
            same_truth = truth[left] == truth[right]
            a, b = result.pseudonyms.get(left), result.pseudonyms.get(right)
            same_pred = bool(a and b and a == b)
            if same_pred and same_truth:
                tp += 1
            elif same_pred:
                fp += 1
            elif same_truth:
                fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f05 = 1.25 * precision * recall / (0.25 * precision + recall) if precision + recall else 0.0
    return {"records": len(records), "true_positive_pairs": tp, "false_positive_pairs": fp,
            "false_negative_pairs": fn, "precision": round(precision, 4), "recall": round(recall, 4),
            "f0_5": round(f05, 4), "false_merges": int(fp > 0),
            "candidate_pairs": len(result.decisions),
            "accepted_match_pairs": sum(decision.state == "match" for decision in result.decisions),
            "ambiguous_pairs": sum(decision.state == "ambiguous" for decision in result.decisions),
            "rejected_pairs": sum(decision.state == "no_match" for decision in result.decisions)}


def linkage_scenarios(seed: int) -> dict[str, Any]:
    rng = random.Random(seed ^ 0xA51D)
    secret = f"synthetic linkage secret {seed:08d}"
    scenarios: dict[str, tuple[list[RecordIdentity], dict[tuple[str, str], str]]] = {}

    def rec(filename: str, patient: str, *, name: str = "", dob: str = "", aadhaar: str = "",
            phone: str = "", village: str = "", age: str = "") -> RecordIdentity:
        item = RecordIdentity(filename, "row:0", "csv")
        for category, value, scope in (("PATIENT_NAME", name, ""), ("DOB", dob, ""),
                                       ("AADHAAR", aadhaar, "global"), ("PHONE", phone, ""),
                                       ("VILLAGE", village, ""), ("AGE", age, "")):
            if value:
                item.add(category, value, scope)
        truth[(item.file, item.loc)] = patient
        return item

    # Exact global ID across formats/hospitals and cross-script name forms.
    truth: dict[tuple[str, str], str] = {}
    latin, deva = generated_name(rng, seed % 31)
    id_1 = str(rng.randrange(10**11, 10**12))
    pair = [rec("site-a.csv", "P1", name=latin, dob="1984-03-18", aadhaar=id_1),
            rec("site-b.json", "P1", name=deva, dob="1984-03-18", aadhaar=id_1)]
    scenarios["cross_hospital_cross_script_strong_id"] = (pair, dict(truth))

    truth = {}
    same = generated_name(rng, (seed + 3) % 31)[0]
    p1, p2 = str(rng.randrange(10**11, 10**12)), str(rng.randrange(10**11, 10**12))
    cases = [rec("homonym-a.csv", "P1", name=same, dob="1979-02-11", aadhaar=p1),
             rec("homonym-b.csv", "P2", name=same, dob="1991-08-24", aadhaar=p2)]
    scenarios["homonym_conflicting_global_ids"] = (cases, dict(truth))

    truth = {}
    cases = [rec("family-a.csv", "P1", name=generated_name(rng, 1)[0], phone="9876543210"),
             rec("family-b.csv", "P2", name=generated_name(rng, 2)[0], phone="9876543210")]
    scenarios["shared_family_phone_weak_only"] = (cases, dict(truth))

    truth = {}
    base = generated_name(rng, 4)[0]
    cases = [rec("variant-a.csv", "P1", name=base, dob="1988-07-12", phone="9123456780"),
             rec("variant-b.csv", "P1", name=base.replace("v", "w", 1), dob="1988-07-12", phone="9123456780")]
    scenarios["similar_spelling_with_independent_evidence"] = (cases, dict(truth))

    truth = {}
    weak = generated_name(rng, 6)[0]
    cases = [rec("weak-a.txt", "P1", name=weak), rec("weak-b.txt", "P1", name=weak)]
    scenarios["name_only_weak_evidence"] = (cases, dict(truth))

    truth = {}
    conflict_name = generated_name(rng, 9)[0]
    cases = [rec("conflict-a.csv", "P1", name=conflict_name, dob="1982-04-09", aadhaar="111122223333"),
             rec("conflict-b.csv", "P1", name=conflict_name, dob="1982-04-09", aadhaar="999988887777")]
    scenarios["same_person_conflicting_global_id"] = (cases, dict(truth))

    truth = {}
    missing_name = generated_name(rng, 12)[0]
    cases = [rec("missing-a.txt", "P1", name=missing_name, dob="1987-06-13"),
             rec("missing-b.txt", "P1", name=missing_name, dob="1987-06-13")]
    scenarios["same_person_missing_strong_ids"] = (cases, dict(truth))

    truth = {}
    inconsistent_name = generated_name(rng, 15)[0]
    shared_id = str(rng.randrange(10**11, 10**12))
    cases = [rec("inconsistent-a.csv", "P1", name=inconsistent_name, dob="1978-02-05",
                 aadhaar=shared_id, village="Kiranpur", age="48"),
             rec("inconsistent-b.csv", "P1", name=inconsistent_name.replace("a", "e", 1), dob="1978-02-05",
                 aadhaar=shared_id, village="Dharampur", age="48")]
    scenarios["same_person_age_location_inconsistency_strong_id"] = (cases, dict(truth))

    output: dict[str, Any] = {}
    for label, (records, labels) in scenarios.items():
        resolved = PatientResolver().resolve(records, Pseudonymizer(secret))
        metrics = pair_metrics(records, labels, resolved)
        metrics["pseudonymized_records"] = resolved.linked_record_count
        metrics["unresolved_records"] = resolved.unresolved_record_count
        output[label] = metrics
    return output


def _risk_summary(records: list[Any]) -> dict[str, Any]:
    profiles = {
        "age": ("age",), "locality": ("locality",), "district": ("district",),
        "pin": ("pin",), "hospital": ("hospital",), "exact_dates": ("event_date_exact",),
        "stay": ("stay",), "diagnosis": ("diagnosis",),
        "age_geography_hospital": ("age", "locality", "tehsil", "district", "pin", "hospital"),
        "age_geography_date": ("age", "locality", "tehsil", "district", "pin", "event_date_exact"),
        "age_date_diagnosis_hospital": ("age", "event_date_exact", "diagnosis", "hospital"),
        "broad_profile": ("age", "locality", "tehsil", "district", "pin", "event_date_exact",
                          "stay", "diagnosis", "hospital"),
    }

    def stats(dimensions: tuple[str, ...]) -> dict[str, Any]:
        groups: Counter[tuple[str, ...]] = Counter(_tuple(record, dimensions) for record in records)
        record_sizes = [groups[_tuple(record, dimensions)] for record in records]
        unique = sum(size == 1 for size in record_sizes)
        return {"equivalence_classes": len(groups), "unique_records": unique,
                "unique_record_percent": round(100 * unique / len(records), 2) if records else 0.0,
                "records_by_class_size": {"1": sum(size == 1 for size in record_sizes),
                                          "2": sum(size == 2 for size in record_sizes),
                                          "3": sum(size == 3 for size in record_sizes),
                                          "4": sum(size == 4 for size in record_sizes),
                                          "5_plus": sum(size >= 5 for size in record_sizes)}}

    return {"records": len(records), "profiles": {name: stats(dimensions)
            for name, dimensions in profiles.items()}}


def _attacker_simulation(profiles: list[dict[str, Any]], sanitized: list[dict[str, Any]], seed: int) -> dict[str, Any]:
    """Voter-roll-style matching with decoys and known visit facts."""
    rng = random.Random(seed ^ 0xC0FFEE)
    registry = [dict(row) for row in profiles]
    villages = [row["village"] for row in profiles]
    for index in range(len(profiles) * 2):
        base = profiles[index % len(profiles)]
        registry.append({"patient_key": f"DECOY-{seed}-{index}",
                         "age": max(0, min(120, base["age"] + rng.choice((-2, -1, 0, 1, 2)))),
                         "village": rng.choice(villages), "district": base["district"],
                         "pin": base["pin"][:3] + f"{rng.randrange(1000):03d}",
                         "hospital": base["hospital"], "admission_date": base["admission_date"],
                         "diagnosis": base["diagnosis"], "stay_duration": base["stay_duration"]})

    raw_unique = released_unique = raw_candidate_counts = released_candidate_counts = date_matches = 0
    for raw, output in zip(profiles, sanitized):
        raw_candidates = [candidate for candidate in registry if
                          candidate["age"] == raw["age"] and candidate["village"] == raw["village"]
                          and candidate["pin"] == raw["pin"] and candidate["hospital"] == raw["hospital"]
                          and candidate["admission_date"] == raw["admission_date"]
                          and candidate["diagnosis"] == raw["diagnosis"]
                          and candidate["stay_duration"] == raw["stay_duration"]]
        age_text = str(output.get("age", ""))
        band = re.fullmatch(r"(\d+)-(\d+)", age_text)
        if band:
            age_ok = lambda candidate: int(band.group(1)) <= candidate["age"] <= int(band.group(2))
        else:
            age_ok = lambda candidate: str(candidate["age"]) == age_text
        location = str(output.get("village", ""))
        if "-level location: " in location:
            coarse = location.split("-level location: ", 1)[1]
            location_ok = lambda candidate: candidate["district"] == coarse
        elif not location or location.startswith("["):
            location_ok = lambda candidate: True
        else:
            location_ok = lambda candidate: candidate["village"] == location
        pin_text = re.sub(r"\D", "", str(output.get("pin", "")))
        pin_ok = lambda candidate: not pin_text or candidate["pin"].startswith(pin_text)
        out_stay = str(output.get("stay_duration", ""))
        stay_range = re.fullmatch(r"(\d+)-(\d+) days", out_stay)
        if stay_range:
            lower, upper = map(int, stay_range.groups())
            stay_ok = lambda candidate: lower <= int(re.search(r"\d+", candidate["stay_duration"]).group()) <= upper
        elif out_stay.endswith("+"):
            threshold = int(out_stay[:-1])
            stay_ok = lambda candidate: int(re.search(r"\d+", candidate["stay_duration"]).group()) >= threshold
        elif not out_stay or out_stay.startswith("["):
            # Suppressed dimensions convey no evidence to the auxiliary attacker.
            stay_ok = lambda candidate: True
        else:
            stay_ok = lambda candidate: candidate["stay_duration"] == out_stay
        released_candidates = [candidate for candidate in registry if
                               age_ok(candidate) and location_ok(candidate) and pin_ok(candidate)
                               and candidate["hospital"] == output.get("hospital")
                               and candidate["diagnosis"] == output.get("diagnosis")
                               and stay_ok(candidate)]
        raw_unique += int(len(raw_candidates) == 1 and raw_candidates[0]["patient_key"] == raw["patient_key"])
        released_unique += int(len(released_candidates) == 1
                               and released_candidates[0]["patient_key"] == raw["patient_key"])
        raw_candidate_counts += len(raw_candidates)
        released_candidate_counts += len(released_candidates)
        date_matches += int(output.get("admission_date") == raw["admission_date"])
    n = len(profiles)
    return {"profiles": n, "registry_size_with_decoys": len(registry),
            "uniquely_matched_raw": raw_unique,
            "uniquely_matched_released": released_unique,
            "raw_unique_match_percent": round(100 * raw_unique / n, 2) if n else 0.0,
            "released_unique_match_percent": round(100 * released_unique / n, 2) if n else 0.0,
            "mean_candidate_count_raw": round(raw_candidate_counts / n, 2) if n else 0.0,
            "mean_candidate_count_released": round(released_candidate_counts / n, 2) if n else 0.0,
            "exact_known_admission_date_matches_after_shift": date_matches}


def run_seed(seed: int, vary_profiles: bool = False) -> dict[str, Any]:
    with tempfile.TemporaryDirectory(prefix="raksha-adversarial-") as temporary:
        work = Path(temporary)
        manifest = generate_corpus(work, seed, vary_profiles=vary_profiles)
        source: Path = manifest["source"]
        output = work / "output"
        secret = f"synthetic adversarial run secret {seed:08d}"
        from src.pipeline import run_pipeline

        try:
            report = run_pipeline(source, output, secret,
                                  {"max_file_bytes": manifest["max_file_bytes"], "max_json_depth": 100})
            pipeline_exit = 0
        except (OSError, ValueError, RuntimeError):
            return {"seed": seed, "pipeline_exit": 1, "runner_error": "pipeline_failed"}

        artifacts = [path for path in output.rglob("*") if path.is_file()]
        haystack = "\n".join(path.relative_to(output).as_posix() + "\n" + path.read_bytes().decode("utf-8", errors="replace")
                              for path in artifacts)
        def canonical(value: str) -> str:
            return unicodedata.normalize("NFKC", value).replace("\u200b", "").casefold()

        leaks: Counter[str] = Counter()
        leak_channels: Counter[str] = Counter()
        leak_formats: Counter[str] = Counter()
        for identity in manifest["identities"]:
            for category, value in identity.items():
                if category in {"patient_key"}:
                    continue
                candidates = [value]
                if category == "name":
                    candidates.extend((value.replace(" ", "\u00a0"), value.replace(" ", "\u200b")))
                if category == "phone":
                    candidates.append(re.sub(r"\D", "", value))
                surfaced = False
                for artifact in artifacts:
                    relative = artifact.relative_to(output).as_posix()
                    body = artifact.read_bytes().decode("utf-8", errors="replace")
                    if any(canonical(candidate) in canonical(relative) for candidate in candidates if candidate):
                        leak_channels["filename"] += 1
                        leak_formats[artifact.suffix.lower() or "(no_extension)"] += 1
                        surfaced = True
                    if any(canonical(candidate) in canonical(body) for candidate in candidates if candidate):
                        channel = "report_or_mapping" if artifact.name in {"report.json", "records.jsonl"} else "content_or_metadata"
                        leak_channels[channel] += 1
                        leak_formats[artifact.suffix.lower() or "(no_extension)"] += 1
                        surfaced = True
                if surfaced:
                    leaks[category] += 1
        missing_clinical = [probe for probe in manifest["clinical"] if probe not in haystack]
        retained_clinical = len(manifest["clinical"]) - len(missing_clinical)
        missing_clinicians = [name for name in manifest["clinicians"] if name not in haystack]
        report = json.loads((output / "report.json").read_text(encoding="utf-8"))
        quarantined = [entry for entry in report["files"] if entry["status"] == "quarantined"]
        exported_bytes = b"".join(path.read_bytes() for path in artifacts)
        input_by_hash = {}
        for path in source.rglob("*"):
            if path.is_file() and not path.is_symlink():
                digest = __import__("hashlib").sha256(path.read_bytes()).hexdigest()
                input_by_hash[digest] = path.read_bytes()
        quarantine_copy = sum(input_by_hash.get(entry["input_sha256"], b"") in exported_bytes
                              for entry in quarantined if input_by_hash.get(entry["input_sha256"]))
        temp_files = sum(path.name.endswith(".tmp") for path in output.rglob("*"))
        unresolved = sum(record.get("patient") is None for line in (output / "records.jsonl").read_text().splitlines()
                         if line for record in [json.loads(line)])

        before_all = collect_privacy_records(source)
        after_all = collect_privacy_records(output / "sanitized")
        digest_to_input = {digest: rel for rel, digest in manifest["input_hashes"].items()}
        output_to_input = {str(entry["output"]).removeprefix("sanitized/"): digest_to_input[entry["input_sha256"]]
                           for entry in report["files"] if entry.get("status") == "sanitized"
                           and entry.get("input_sha256") in digest_to_input}
        before_by_ref = {(item.file, item.loc): item for item in before_all}
        after_by_ref = {(output_to_input.get(item.file, item.file), item.loc): item for item in after_all}
        common = set(before_by_ref).intersection(after_by_ref)
        before = [before_by_ref[key] for key in sorted(common)]
        after = [after_by_ref[key] for key in sorted(common)]
        sanitized_json = json.loads((output / "sanitized/records/nested.json").read_text(encoding="utf-8"))["records"]
        def count_key(node: Any, wanted: str) -> int:
            if isinstance(node, dict):
                return sum(int(str(key).casefold() == wanted) + count_key(value, wanted)
                           for key, value in node.items())
            if isinstance(node, list):
                return sum(count_key(value, wanted) for value in node)
            return 0

        def collect_stay_values(node: Any) -> list[str]:
            if isinstance(node, dict):
                values = [str(value) for key, value in node.items()
                          if str(key).casefold() == "stay_duration" and isinstance(value, str)]
                return values + [value for child in node.values() for value in collect_stay_values(child)]
            if isinstance(node, list):
                return [value for child in node for value in collect_stay_values(child)]
            return []

        stay_key_count = count_key(sanitized_json, "stay_duration")
        stay_value_counts = Counter(collect_stay_values(sanitized_json))
        expected_stay_values = Counter({"3 days": 32, "2 days": 16})
        exact_stay_values_retained = sum((stay_value_counts & expected_stay_values).values())
        attacker = _attacker_simulation(manifest["qi_profiles"], sanitized_json, seed)
        linkage = linkage_scenarios(seed)
        report_path = output / "report.json"
        return {
            "seed": seed,
            "generator_version": "phase6-synthetic-v1-varied" if vary_profiles else "phase6-synthetic-v1",
            "pipeline_exit": pipeline_exit,
            "files": {"input": len(report["files"]), "sanitized": report["counts"]["files_sanitized"],
                      "quarantined": len(quarantined), "records": report["counts"]["records_processed"]},
            "privacy_action_counts": report.get("privacy", {}).get("actions", {}),
            "pii_surface_leak_counts_by_generated_field": dict(sorted(leaks.items())),
            "pii_surface_leak_total": sum(leaks.values()),
            "pii_surface_leak_channels": dict(sorted(leak_channels.items())),
            "pii_surface_leak_formats": dict(sorted(leak_formats.items())),
            "clinical_probes_retained": retained_clinical,
            "clinical_probe_total": len(manifest["clinical"]),
            "clinical_probes_missing": missing_clinical,
            "stay_duration_fields_preserved": stay_key_count,
            "stay_duration_fields_generalized": report.get("privacy", {}).get("actions", {}).get("generalized_stay", 0),
            "stay_duration_exact_values_retained": exact_stay_values_retained,
            "stay_duration_exact_values_expected": sum(expected_stay_values.values()),
            "impossible_calendar_dates_generalized": report.get("privacy", {}).get("actions", {}).get(
                "generalized_invalid_date", 0),
            "clinician_names_preserved": len(manifest["clinicians"]) - len(missing_clinicians),
            "clinician_name_total": len(manifest["clinicians"]),
            "quarantined_input_count": len(quarantined),
            "raw_input_copies_found_in_output": quarantine_copy,
            "temporary_artifacts_left": temp_files,
            "unresolved_link_records": unresolved,
            "linkage_scenarios": linkage,
            "reidentification": {"raw": _risk_summary(before), "sanitized": _risk_summary(after)},
            "auxiliary_registry_attack": attacker,
            "secret_in_output_or_logs": secret in haystack,
            "input_unchanged": manifest["input_hashes"] == {
                path.relative_to(source).as_posix(): __import__("hashlib").sha256(path.read_bytes()).hexdigest()
                for path in source.rglob("*") if path.is_file() and not path.is_symlink()},
            "report_contains_generated_identity_surfaces": any(x["name"] in report_path.read_text(encoding="utf-8")
                                                               for x in manifest["identities"]),
        }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--seeds", nargs="+", type=int, default=[61027, 93811])
    parser.add_argument("--varied-seeds", nargs="+", type=int, default=[],
                        help="run independently varied names, locations, ages, dates and diagnoses")
    parser.add_argument("--summary", type=Path, help="write aggregate JSON summary (no generated PII)")
    args = parser.parse_args()
    summaries = [run_seed(seed) for seed in args.seeds]
    summaries.extend(run_seed(seed, vary_profiles=True) for seed in args.varied_seeds)
    payload = {"suite": "Secret Wards independent adversarial suite", "version": "phase6-synthetic-v1",
               "seeds": args.seeds, "varied_seeds": args.varied_seeds, "runs": summaries}
    rendered = json.dumps(payload, indent=2, sort_keys=True) + "\n"
    if args.summary:
        args.summary.parent.mkdir(parents=True, exist_ok=True)
        args.summary.write_text(rendered, encoding="utf-8")
    print(rendered, end="")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
