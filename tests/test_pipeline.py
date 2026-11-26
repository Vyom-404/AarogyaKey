from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.pipeline import run_pipeline



class PipelineTests(unittest.TestCase):

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.inp = self.root / "input"
        self.out = self.root / "output"
        self.inp.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_it(self) -> dict:
        return run_pipeline(self.inp, self.out, "unit-test-secret", {"max_json_depth": 20})

    def test_csv_text_and_row_locations(self) -> None:
        (self.inp / "records.csv").write_text("name,value\nExample,5 mg\n", encoding="utf-8")
        report = self.run_it()
        self.assertEqual(report["counts"]["files_sanitized"], 1)
        self.assertEqual((self.out / "sanitized/records.csv").read_text(), "name,value\n[PATIENT_NAME],5 mg\n")
        records = [json.loads(line) for line in (self.out / "records.jsonl").read_text().splitlines()]
        self.assertEqual(records, [{"file": "sanitized/records.csv", "loc": "row:0", "patient": None}])

    def test_nested_json_pointer_and_fhir_document_location(self) -> None:
        (self.inp / "visits.json").write_text('{"visits":[{"x":1},{"x":2}]}', encoding="utf-8")
        (self.inp / "bundle.json").write_text(
            '{"resourceType":"Bundle","type":"collection","entry":[]}', encoding="utf-8"
        )
        self.run_it()
        records = [json.loads(line) for line in (self.out / "records.jsonl").read_text().splitlines()]
        self.assertIn({"file": "sanitized/visits.json", "loc": "/visits/1", "patient": None}, records)
        self.assertIn({"file": "sanitized/bundle.json", "loc": "doc", "patient": None}, records)

    def test_fhir_patient_name_is_removed_but_clinical_names_remain(self) -> None:
        bundle = {
            "resourceType": "Bundle", "type": "collection", "entry": [
                {"resource": {"resourceType": "Organization", "name": "Example Medical Center"}},
                {"resource": {"resourceType": "Patient", "name": [{"given": ["Aarav"], "family": "Kulkarni"}]}},
                {"resource": {"resourceType": "Condition", "code": {"text": "Parkinson's disease"}}},
            ],
        }
        (self.inp / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")
        self.run_it()
        result = json.loads((self.out / "sanitized/bundle.json").read_text(encoding="utf-8"))
        self.assertEqual(result["entry"][0]["resource"]["name"], "Example Medical Center")
        self.assertEqual(result["entry"][1]["resource"]["name"][0]["given"][0], "[PATIENT_NAME]")
        self.assertEqual(result["entry"][1]["resource"]["name"][0]["family"], "[PATIENT_NAME]")
        self.assertEqual(result["entry"][2]["resource"]["code"]["text"], "Parkinson's disease")

    def test_nested_diagnosis_terms_are_not_matched_as_patient_names(self) -> None:
        data = {
            "visits": [{
                "patient_name": "Aarav Kulkarni",
                "diagnosis": {"coding": [{"display": "Parkinson's disease"}]},
            }]
        }
        (self.inp / "visits.json").write_text(json.dumps(data), encoding="utf-8")
        self.run_it()
        result = json.loads((self.out / "sanitized/visits.json").read_text(encoding="utf-8"))
        self.assertEqual(result["visits"][0]["patient_name"], "[PATIENT_NAME]")
        self.assertEqual(result["visits"][0]["diagnosis"]["coding"][0]["display"], "Parkinson's disease")

    def test_record_local_patient_name_is_removed_from_notes_only_in_same_record(self) -> None:
        data = {
            "visits": [
                {"patient": {"name": "Aarav Kulkarni"}, "notes": "Seen with Aarav Kulkarni; dengue improving."},
                {"patient": {"name": "Nisha Patel"}, "notes": "Dr. Aarav Kulkarni reviewed HbA1c 7.2%."},
            ]
        }
        (self.inp / "visits.json").write_text(json.dumps(data), encoding="utf-8")
        self.run_it()
        result = json.loads((self.out / "sanitized/visits.json").read_text(encoding="utf-8"))
        self.assertNotIn("Aarav Kulkarni", result["visits"][0]["notes"])
        self.assertIn("Dr. Aarav Kulkarni", result["visits"][1]["notes"])
        self.assertEqual(result["visits"][1]["patient"]["name"], "[PATIENT_NAME]")

    def test_patient_first_name_in_local_kinship_reference_is_removed(self) -> None:
        data = {"visits": [{"patient": {"name": "Asha Rajput"},
                            "notes": "Asha's attendant called. Asha didi ka BP 120/80."}]}
        (self.inp / "visit.json").write_text(json.dumps(data), encoding="utf-8")
        self.run_it()
        notes = json.loads((self.out / "sanitized/visit.json").read_text(encoding="utf-8"))["visits"][0]["notes"]
        self.assertNotIn("Asha", notes)
        self.assertIn("BP 120/80", notes)

    def test_nested_address_metadata_and_fhir_extension_are_sanitized(self) -> None:
        data = {
            "resourceType": "Patient",
            "address": [{"line": ["House 9, Lake Road"], "city": "Example City", "postalCode": "226021"}],
            "meta": {"source_path": "imports/Example Patient.json", "raised_by": {"name": "Rohan Das"}},
            "extension": [{"url": "relative-name", "valueString": "Meera Das"}],
        }
        (self.inp / "patient.json").write_text(json.dumps(data), encoding="utf-8")
        self.run_it()
        result = json.loads((self.out / "sanitized/patient.json").read_text(encoding="utf-8"))
        self.assertEqual(result["address"][0]["line"][0], "[ADDRESS]")
        self.assertEqual(result["address"][0]["city"], "[ADDRESS]")
        self.assertEqual(result["address"][0]["postalCode"], "[PIN]")
        self.assertEqual(result["meta"]["source_path"], "[METADATA]")
        self.assertEqual(result["meta"]["raised_by"]["name"], "[PATIENT_NAME]")

    def test_fhir_identifier_in_encounter_is_redacted(self) -> None:
        data = {"resourceType": "Bundle", "type": "collection", "entry": [
            {"resource": {"resourceType": "Encounter", "identifier": [{"value": "ADM000161"}],
                          "diagnosis": [{"display": "Hypertension"}]}}
        ]}
        (self.inp / "fhir.json").write_text(json.dumps(data), encoding="utf-8")
        self.run_it()
        result = json.loads((self.out / "sanitized/fhir.json").read_text(encoding="utf-8"))
        self.assertEqual(result["entry"][0]["resource"]["identifier"][0]["value"], "[MRN]")
        self.assertEqual(result["entry"][0]["resource"]["diagnosis"][0]["display"], "Hypertension")

    def test_utf16_tsv_is_written_as_utf8(self) -> None:
        (self.inp / "rows.tsv").write_bytes("field\tvalue\nα\tclinical\n".encode("utf-16"))
        self.run_it()
        raw_output = (self.out / "sanitized/rows.tsv").read_bytes()
        self.assertEqual(raw_output.decode("utf-8"), "field\tvalue\nα\tclinical\n")

    def test_demographic_city_with_village_form_is_redacted_conservatively(self) -> None:
        (self.inp / "registration").mkdir()
        (self.inp / "registration" / "patients.csv").write_text("City,District\nExampledih,Hardoi\n", encoding="utf-8")
        (self.inp / "lab.csv").write_text("City,Result\nExample City,Normal\n", encoding="utf-8")
        self.run_it()
        registration = (self.out / "sanitized/registration/patients.csv").read_text(encoding="utf-8")
        lab = (self.out / "sanitized/lab.csv").read_text(encoding="utf-8")
        self.assertIn("[VILLAGE],Hardoi", registration)
        self.assertIn("Example City,Normal", lab)
