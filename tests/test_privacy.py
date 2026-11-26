from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.privacy import DateShifter, age_band, build_privacy_actions, collect_privacy_records, equivalence_summary
from src.privacy.date_shifter import format_date, month_precision, parse_date
from src.privacy.extractor import PrivacyRecord
from src.pipeline import run_pipeline


class DateShiftTests(unittest.TestCase):
    def test_patient_offsets_are_stable_independent_and_secret_keyed(self) -> None:
        a = DateShifter("phase4 deterministic test secret").offset_days("PSN-AAA")
        self.assertEqual(a, DateShifter("phase4 deterministic test secret").offset_days("PSN-AAA"))
        self.assertNotEqual(a, DateShifter("phase4 rotated test secret 2").offset_days("PSN-AAA"))
        self.assertNotEqual(a, DateShifter("phase4 deterministic test secret").offset_days("PSN-BBB"))

    def test_leap_day_and_month_year_boundaries_shift_as_calendar_dates(self) -> None:
        shifter = DateShifter("phase4 deterministic test secret", maximum_days=365)
        leap = parse_date("2024-02-29")
        end_month = parse_date("31/12/2024")
        self.assertIsNotNone(leap)
        self.assertIsNotNone(end_month)
        self.assertIsNotNone(shifter.shift(leap.value, "PSN-AAA"))
        shifted = shifter.shift(end_month.value, "PSN-AAA")
        self.assertGreaterEqual(shifted.year, 2023)
        self.assertLessEqual(shifted.year, 2026)

    def test_unresolved_dates_keep_month_and_remove_exact_day(self) -> None:
        self.assertEqual(month_precision("2025-09-17"), "2025-09")
        self.assertEqual(month_precision("17/09/2025"), "09/2025")
        record = PrivacyRecord("hospital/unresolved.csv", "row:0", "csv")
        record.add("event_date", "2025-09-17", "visit_date", (0,))
        actions = build_privacy_actions([record], {}, "phase4 deterministic test secret",
                                        {"unresolved_date_precision": "year"})
        self.assertEqual(actions[(record.file, record.loc)][0].replacement, "2025")


class GeneralizationTests(unittest.TestCase):
    def test_age_bands_are_truthful_for_children_adults_and_seniors(self) -> None:
        for age in (0, 4, 5, 14, 15, 17, 18, 19, 20, 24, 25, 84, 85, 120):
            band = age_band(age)
            if band.endswith("+"):
                self.assertGreaterEqual(age, int(band[:-1]))
            else:
                lower, upper = map(int, band.split("-"))
                self.assertLessEqual(lower, age)
                self.assertGreaterEqual(upper, age)
        self.assertEqual(age_band(3), "0-4")
        self.assertEqual(age_band(16), "15-17")
        self.assertEqual(age_band(85), "85+")

    def test_stay_duration_generalization_preserves_clinical_interval_bucket(self) -> None:
        self.assertEqual("4-7 days", __import__("src.privacy.generalization", fromlist=["generalize_stay"]).generalize_stay("6 days"))


class RiskAndPipelineTests(unittest.TestCase):
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


if __name__ == "__main__":
    unittest.main()
