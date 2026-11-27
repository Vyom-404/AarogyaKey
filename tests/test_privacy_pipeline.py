from __future__ import annotations

import datetime as dt
import json
import tempfile
import time
import unittest
from pathlib import Path
from unittest.mock import patch

from src.privacy import DateShifter, age_band, build_privacy_actions, collect_privacy_records, equivalence_summary
from src.privacy.date_shifter import format_date, month_precision, parse_date
from src.privacy.extractor import PrivacyRecord
from src.pipeline import run_pipeline


class RiskAndPipelineTests(unittest.TestCase):
    def test_shifted_event_date_is_generalized_if_it_collides_with_any_original_dob(self) -> None:
        secret = "synthetic collision regression secret"
        patient = "PSN-SYNTHETIC-COLLISION"
        base = parse_date("2020-06-15").value.date()
        baseline_offset = DateShifter(secret).offset_days(patient)
        protected_dob = base + dt.timedelta(days=baseline_offset)

        dob_record = PrivacyRecord("hospital-a/demographics.csv", "row:0", "csv")
        dob_record.add("dob", protected_dob.isoformat(), "dob", (2,))
        collision_record = PrivacyRecord("hospital-b/visits.csv", "row:0", "csv")
        collision_record.add("event_date", base.isoformat(), "visit_date", (3,))
        next_visit = PrivacyRecord("hospital-b/visits.csv", "row:1", "csv")
        next_visit.add("event_date", (base + dt.timedelta(days=7)).isoformat(), "visit_date", (3,))
        pseudonyms = {
            (collision_record.file, collision_record.loc): patient,
            (next_visit.file, next_visit.loc): patient,
        }

        actions = build_privacy_actions([dob_record, collision_record, next_visit], pseudonyms, secret)
        collision_action = actions[(collision_record.file, collision_record.loc)][0]
        next_action = actions[(next_visit.file, next_visit.loc)][0]

        self.assertEqual(collision_action.action, "generalized_date_collision")
        self.assertEqual(collision_action.replacement, (base + dt.timedelta(days=baseline_offset)).strftime("%Y-%m"))
        self.assertEqual(next_action.action, "shifted_date")
        shifted_next = parse_date(next_action.replacement).value.date()
        self.assertEqual((shifted_next - (base + dt.timedelta(days=7))).days, baseline_offset)

    def test_exact_stay_duration_is_preserved_by_default(self) -> None:
        record = PrivacyRecord("hospital/a.json", "/records/0", "json")
        record.add("stay", "9 days", "stay_duration", ("records", 0, "stay_duration"))
        actions = build_privacy_actions([record], {}, "phase4 deterministic test secret")
        self.assertNotIn("generalized_stay", {action.action for action in actions.get((record.file, record.loc), [])})

    def test_stay_bucketing_remains_an_explicit_opt_in(self) -> None:
        record = PrivacyRecord("hospital/a.json", "/records/0", "json")
        record.add("stay", "9 days", "stay_duration", ("records", 0, "stay_duration"))
        opted_in = build_privacy_actions(
            [record], {}, "phase4 deterministic test secret", {"preserve_exact_stay_duration": False}
        )
        self.assertIn("generalized_stay", {action.action for action in opted_in[(record.file, record.loc)]})

    def test_rare_diagnosis_generalizes_only_for_low_k_record(self) -> None:
        record = PrivacyRecord("hospital/a.json", "/records/0", "json")
        record.add("age", "41", "age", ("records", 0, "age"))
        record.add("diagnosis", "Q99.9", "diagnosis", ("records", 0, "diagnosis"))
        record.add("event_date", "2025-04-12", "visit_date", ("records", 0, "visit_date"))
        actions = build_privacy_actions([record], {}, "phase4 deterministic test secret",
                                        {"rare_diagnosis_action": "generalize"})
        self.assertIn("generalized_diagnosis", {action.action for action in actions[(record.file, record.loc)]})

    def test_rare_diagnosis_is_preserved_by_default_for_medical_integrity(self) -> None:
        record = PrivacyRecord("hospital/a.json", "/records/0", "json")
        record.add("diagnosis", "E03.9", "diagnosis", ("records", 0, "diagnosis"))
        actions = build_privacy_actions([record], {}, "phase4 deterministic test secret")
        self.assertNotIn("generalized_diagnosis", {a.action for a in actions.get((record.file, record.loc), [])})

    def test_equivalence_summary_reports_only_aggregates(self) -> None:
        before = [PrivacyRecord("a/h.csv", "row:0", "csv"), PrivacyRecord("b/h.csv", "row:0", "csv")]
        before[0].add("age", "44", "age")
        before[1].add("age", "45", "age")
        summary = equivalence_summary(before, before, {"minimum_equivalence_class": 3})
        encoded = json.dumps(summary)
        self.assertIn("unique_record_percent", encoded)
        self.assertNotIn("44", encoded)
        self.assertEqual(summary["minimum_k_target"], 3)

    def test_pipeline_generalizes_age_location_dates_and_keeps_medical_values(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as output_parent:
            root = Path(input_dir)
            (root / "sanjeevani").mkdir()
            (root / "sanjeevani" / "visits.csv").write_text(
                "patient_name,mrn,age,dob,admission_date,discharge_date,village,tehsil,district,pincode,diagnosis,medicine,dose\n"
                "Kiran Shah,MRN-551,47,12/04/1979,2024-02-29,2024-03-04,Rampur,North Block,Sample District,226123,Dengue,Dolo,650 mg BD x 5 days\n"
                "Meera Das,MRN-552,46,13/04/1979,2024-03-01,2024-03-05,Rampur,North Block,Sample District,226123,Dengue,Dolo,650 mg BD x 5 days\n"
                "Ravi Sen,MRN-553,48,14/04/1979,2024-03-02,2024-03-06,Rampur,North Block,Sample District,226123,Dengue,Dolo,650 mg BD x 5 days\n",
                encoding="utf-8",
            )
            output = Path(output_parent) / "out"
            report = run_pipeline(root, output, "phase4 deterministic test secret")
            safe = (output / "sanitized/sanjeevani/visits.csv").read_text()
            self.assertIn("45-49", safe)
            self.assertIn("Tehsil-level location: North Block", safe)
            self.assertIn("226***", safe)
            self.assertNotIn("12/04/1979", safe)
            self.assertNotIn("2024-02-29", safe)
            self.assertIn("Dengue", safe)
            self.assertIn("Dolo", safe)
            self.assertIn("650 mg BD x 5 days", safe)
            self.assertGreater(report["counts"]["records_generalized"], 0)
            self.assertNotIn("Kiran Shah", (output / "report.json").read_text())

    def test_unresolved_text_dates_are_month_generalized(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as output_parent:
            root = Path(input_dir)
            (root / "note.txt").write_text("Visit Date: 2026-11-26\nDiagnosis: asthma\n", encoding="utf-8")
            output = Path(output_parent) / "out"
            run_pipeline(root, output, "phase4 deterministic test secret")
            clean = (output / "sanitized/note.txt").read_text()
            self.assertIn("2026-11", clean)
            self.assertNotIn("2026-11-26", clean)
            self.assertIn('"patient": null', (output / "records.jsonl").read_text())

    def test_visit_identifiers_are_not_classified_as_dates_and_months_remain_measurable(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir:
            root = Path(input_dir)
            (root / "visits.json").write_text(json.dumps({"visits": [{
                "visit_id": "OPD/26/02/00085", "visit_date": "2026-03-04"}]}), encoding="utf-8")
            structured = collect_privacy_records(root)[0]
            self.assertEqual([(f.field_name, f.value) for f in structured.fields if f.kind == "event_date"],
                             [("visit_date", "2026-03-04")])
            (root / "note.txt").write_text(
                "Visit ID: OPD/26/02/00085\nDate: OPD/26/02/00085\nDate: 05-2026\n", encoding="utf-8")
            text_record = next(r for r in collect_privacy_records(root) if r.file == "note.txt")
            self.assertEqual([f.value for f in text_record.fields if f.kind == "event_date"], ["05-2026"])

    def test_metadata_dates_shift_without_exposing_original_value(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as output_parent:
            root = Path(input_dir)
            (root / "record.json").write_text(json.dumps({"visits": [{"patient": {"mrn": "MR-991", "name": "Asha Rao"},
                "visit_date": "2025-06-10", "meta": {"created_at": "2025-06-10T08:30:00Z",
                "audit_stamp": "2025-06-10"},
                "diagnosis": "asthma"}]}), encoding="utf-8")
            output = Path(output_parent) / "out"
            run_pipeline(root, output, "phase4 deterministic test secret")
            clean = (output / "sanitized/record.json").read_text()
            self.assertNotIn("2025-06-10", clean)
            self.assertNotIn("2025-06-10T08:30:00Z", clean)

    def test_same_global_patient_gets_consistent_shift_across_hospitals(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as output_parent:
            root = Path(input_dir)
            for hospital, date in (("hospital_a", "2024-02-29"), ("hospital_b", "2024-03-05")):
                folder = root / hospital
                folder.mkdir()
                (folder / "visits.csv").write_text(
                    "patient_name,aadhaar,visit_date,diagnosis,dose\n"
                    f"Aarav Mehta,234567890123,{date},asthma,5 mg BD\n", encoding="utf-8")
            output = Path(output_parent) / "out"
            report = run_pipeline(root, output, "phase4 deterministic test secret")
            records = [json.loads(line) for line in (output / "records.jsonl").read_text().splitlines()]
            self.assertEqual(report["counts"]["records_linked"], 2)
            self.assertEqual(records[0]["patient"], records[1]["patient"])
            dates = []
            for record in records:
                row = (output / record["file"]).read_text().splitlines()[1].split(",")
                dates.append(parse_date(row[2]).value.date())
                self.assertEqual(row[3:], ["asthma", "5 mg BD"])
            self.assertEqual((dates[1] - dates[0]).days, 5)

    def test_full_dates_in_output_filenames_are_removed(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as output_parent:
            root = Path(input_dir)
            (root / "visit_2025-06-10.txt").write_text("Diagnosis: asthma\n", encoding="utf-8")
            output = Path(output_parent) / "out"
            run_pipeline(root, output, "phase4 deterministic test secret")
            exported_paths = [entry["output"] for entry in json.loads((output / "report.json").read_text())["files"]]
            self.assertFalse(any("2025-06-10" in str(name) for name in exported_paths))

    def test_report_timing_includes_preprocessing(self) -> None:
        import src.pipeline as pipeline

        original = pipeline.harvest_input_names

        def delayed_harvest(*args, **kwargs):
            time.sleep(0.25)
            return original(*args, **kwargs)

        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as output_parent:
            (Path(input_dir) / "note.txt").write_text("Diagnosis: asthma\n", encoding="utf-8")
            output = Path(output_parent) / "out"
            with patch("src.pipeline.harvest_input_names", side_effect=delayed_harvest):
                report = run_pipeline(Path(input_dir), output, "phase7 timing test secret")
            self.assertGreaterEqual(report["timing"]["seconds"], 0.2)


