from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.detection import PIIDetector
from src.linkage import PatientResolver, Pseudonymizer, RecordIdentity
from src.linkage.extractor import extract_file_records
from src.linkage.extractor import _name_forms
from src.pipeline import run_pipeline


def record(file: str, name: str = "", *, dob: str = "", mrn: str = "", scope: str = "", relative: str = "") -> RecordIdentity:
    item = RecordIdentity(file, "row:0", "csv")
    if name:
        item.add("PATIENT_NAME", name)
    if dob:
        item.add("DOB", dob)
    if mrn:
        item.add("MRN", mrn, scope)
    if relative:
        item.add("RELATIVE_NAME", relative)
    return item


class PseudonymizerTests(unittest.TestCase):
    def test_deterministic_rotation_and_distinct_anchors(self) -> None:
        a = Pseudonymizer("a sufficiently long secret").pseudonym(("id", "A-123"))
        same = Pseudonymizer("a sufficiently long secret").pseudonym(("id", "A-123"))
        rotated = Pseudonymizer("rotated sufficiently long secret").pseudonym(("id", "A-123"))
        other = Pseudonymizer("a sufficiently long secret").pseudonym(("id", "B-456"))
        self.assertEqual(a, same)
        self.assertNotEqual(a, rotated)
        self.assertNotEqual(a, other)
        self.assertTrue(a.startswith("PSN-"))

    def test_short_secret_rejected(self) -> None:
        with self.assertRaises(ValueError):
            Pseudonymizer("short")


class ResolverTests(unittest.TestCase):
    def setUp(self) -> None:
        self.pseudo = Pseudonymizer("unit-test-secret")
        self.resolver = PatientResolver()

    def test_shared_global_id_links_across_sites_and_keeps_anchor_stable(self) -> None:
        a = record("one.csv", "Aarav Mehta", mrn="AB1234", scope="site-a")
        a.add("AADHAAR", "123456789012", "global")
        b = record("two.csv", "Aarav Mehta", mrn="XY8821", scope="site-b")
        b.add("AADHAAR", "123456789012", "global")
        result = self.resolver.resolve([a, b], self.pseudo)
        self.assertEqual(result.pseudonyms[(a.file, a.loc)], result.pseudonyms[(b.file, b.loc)])
        anchor_with_more_id = record("three.csv", "Aarav Mehta", mrn="ZZ9921", scope="site-c")
        anchor_with_more_id.add("AADHAAR", "123456789012", "global")
        enlarged = self.resolver.resolve([a, b, anchor_with_more_id], self.pseudo)
        self.assertEqual(result.pseudonyms[(a.file, a.loc)], enlarged.pseudonyms[(a.file, a.loc)])

    def test_name_dob_transliteration_signal_links(self) -> None:
        a = record("latin.csv", dob="1988-02-03")
        b = record("devanagari.csv", dob="1988-02-03")
        for value in _name_forms("mohammad khan"):
            a.add("PATIENT_NAME", value)
        for value in _name_forms("मोहम्मद खान"):
            b.add("PATIENT_NAME", value)
        result = self.resolver.resolve([a, b], self.pseudo)
        self.assertEqual(result.pseudonyms.get((a.file, a.loc)), result.pseudonyms.get((b.file, b.loc)))

    def test_same_name_with_conflicting_dob_remains_unlinked(self) -> None:
        a = record("a.csv", "Riya Verma", dob="1980-01-02")
        b = record("b.csv", "Riya Verma", dob="1990-01-02")
        result = self.resolver.resolve([a, b], self.pseudo)
        self.assertNotEqual(result.pseudonyms[(a.file, a.loc)], result.pseudonyms[(b.file, b.loc)])

    def test_insufficient_name_only_evidence_stays_null(self) -> None:
        a, b = record("a.csv", "Kabir Singh"), record("b.csv", "Kabir Singh")
        result = self.resolver.resolve([a, b], self.pseudo)
        self.assertFalse(result.pseudonyms)

    def test_shared_family_phone_without_independent_clue_stays_null(self) -> None:
        a = record("a.csv", "Anaya Rao")
        b = record("b.csv", "Dev Rao")
        a.add("PHONE", "9876543210")
        b.add("PHONE", "9876543210")
        result = self.resolver.resolve([a, b], self.pseudo)
        self.assertNotEqual(result.pseudonyms.get((a.file, a.loc)), result.pseudonyms.get((b.file, b.loc)))

    def test_relationship_plus_conflicting_phone_blocks_homonym_merge(self) -> None:
        a = record("hospital-a.txt", "Nisha Khan", relative="Imran Khan")
        b = record("hospital-b.txt", "Nisha Khan", relative="Imran Khan")
        a.add("PHONE", "9876543210")
        b.add("PHONE", "9123456780")
        result = self.resolver.resolve([a, b], self.pseudo)
        self.assertTrue((a.file, a.loc) not in result.pseudonyms or (b.file, b.loc) not in result.pseudonyms
                        or result.pseudonyms[(a.file, a.loc)] != result.pseudonyms[(b.file, b.loc)])

    def test_mrn_namespace_conflicts_block_false_merge(self) -> None:
        a = record("a.csv", "Isha Patel", mrn="MRN-12", scope="hospital-a")
        b = record("b.csv", "Isha Patel", mrn="MRN-14", scope="hospital-a")
        result = self.resolver.resolve([a, b], self.pseudo)
        self.assertNotEqual(result.pseudonyms[(a.file, a.loc)], result.pseudonyms[(b.file, b.loc)])

    def test_same_scoped_mrn_and_phone_link_fragmented_rows_without_name_or_dob(self) -> None:
        a = record("hospital-a/registration.csv", mrn="MRN-612", scope="hospital-a")
        b = record("hospital-a/lab.csv", mrn="MRN-612", scope="hospital-a")
        a.add("PHONE", "9876543210")
        b.add("PHONE", "9876543210")
        result = self.resolver.resolve([a, b], self.pseudo)
        self.assertEqual(result.pseudonyms[(a.file, a.loc)], result.pseudonyms[(b.file, b.loc)])

    def test_exact_same_hospital_scoped_mrn_links_without_other_fields(self) -> None:
        a = record("hospital-a/registration.csv", mrn="MRN-614", scope="hospital-a")
        b = record("hospital-a/lab.csv", mrn="MRN-614", scope="hospital-a")
        result = self.resolver.resolve([a, b], self.pseudo)
        self.assertEqual(result.pseudonyms[(a.file, a.loc)], result.pseudonyms[(b.file, b.loc)])


class ExtractionAndPipelineTests(unittest.TestCase):
    def test_devanagari_tsv_headers_are_linkage_fields_and_values_are_sanitized(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as output_parent:
            root = Path(input_dir)
            source = root / "hindi.tsv"
            source.write_text(
                "नाम\tपिता_का_नाम\tमोबाइल\tगांव\tपिन\tडॉक्टर\tनिदान\tदवा\n"
                "कविता शर्मा\tरमेश शर्मा\t9876543210\tरामपुर\t226021\tडॉ. सीमा वर्मा\tबुखार\tपैरासिटामोल 500 mg\n",
                encoding="utf-8",
            )
            identities = extract_file_records(source, "hindi.tsv", PIIDetector())
            categories = {signal.category for signal in identities[0].signals}
            self.assertTrue({"PATIENT_NAME", "RELATIVE_NAME", "PHONE", "VILLAGE", "PIN"}.issubset(categories))

            out = Path(output_parent) / "output"
            run_pipeline(root, out, "this is a sufficiently long secret")
            exported = (out / "sanitized/hindi.tsv").read_text(encoding="utf-8")
            self.assertNotIn("कविता शर्मा", exported)
            self.assertNotIn("रमेश शर्मा", exported)
            self.assertIn("डॉ. सीमा वर्मा", exported)
            self.assertIn("पैरासिटामोल 500 mg", exported)

    def test_nested_patient_json_identifier_is_extracted(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "records.json"
            path.write_text(json.dumps({"records": [{"patient": {"name": "Meera Das", "mrn": "MR-992"},
                                                    "diagnosis": "asthma"}]}), encoding="utf-8")
            records = extract_file_records(path, "records.json", PIIDetector())
        self.assertEqual(records[0].loc, "/records/0")
        self.assertIn("MRN", {signal.category for signal in records[0].signals})

    def test_linked_patient_pseudonym_is_in_records_and_export(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as output_parent:
            root = Path(input_dir)
            (root / "a.csv").write_text("patient_name,mrn,dob\nAarav Mehta,MR-481,1980-01-01\n", encoding="utf-8")
            (root / "b.csv").write_text("patient_name,mrn,dob\nAarav Mehta,MR-991,1980-01-01\n", encoding="utf-8")
            out = Path(output_parent) / "output"
            report = run_pipeline(root, out, "this is a sufficiently long secret")
            records = [json.loads(line) for line in (out / "records.jsonl").read_text().splitlines()]
            self.assertEqual(report["counts"]["records_linked"], 2)
            self.assertEqual(records[0]["patient"], records[1]["patient"])
            self.assertIn(records[0]["patient"], (out / records[0]["file"]).read_text())
            self.assertIn(records[1]["patient"], (out / records[1]["file"]).read_text())

    def test_nested_json_gets_pseudonym_without_changing_diagnosis(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as output_parent:
            root = Path(input_dir)
            payload = {"visits": [{"patient": {"name": "Meera Das", "mrn": "MRN-777"},
                                   "diagnosis": "type 2 diabetes", "dose": "500 mg BD"}]}
            (root / "visits.json").write_text(json.dumps(payload), encoding="utf-8")
            out = Path(output_parent) / "output"
            run_pipeline(root, out, "this is a sufficiently long secret")
            patient = json.loads((out / "records.jsonl").read_text().splitlines()[0])["patient"]
            exported = json.loads((out / "sanitized/visits.json").read_text())
            self.assertEqual(exported["visits"][0]["patient"]["mrn"], patient)
            self.assertEqual(exported["visits"][0]["diagnosis"], "type 2 diabetes")
            self.assertEqual(exported["visits"][0]["dose"], "500 mg BD")

    def test_fhir_bundle_replaces_only_patient_identity_and_keeps_clinical_data(self) -> None:
        with tempfile.TemporaryDirectory() as input_dir, tempfile.TemporaryDirectory() as output_parent:
            root = Path(input_dir)
            bundle = {"resourceType": "Bundle", "type": "collection", "entry": [
                {"resource": {"resourceType": "Patient", "id": "p1", "identifier": [
                    {"type": {"text": "Medical Record Number"}, "value": "MR-889"}],
                    "name": [{"text": "Asha Menon"}]}},
                {"resource": {"resourceType": "Observation", "status": "final", "code": {"text": "Hemoglobin"},
                               "valueQuantity": {"value": 10.4, "unit": "g/dL"}}},
            ]}
            (root / "bundle.json").write_text(json.dumps(bundle), encoding="utf-8")
            out = Path(output_parent) / "output"
            run_pipeline(root, out, "this is a sufficiently long secret")
            patient = json.loads((out / "records.jsonl").read_text().splitlines()[0])["patient"]
            exported = json.loads((out / "sanitized/bundle.json").read_text())
            self.assertEqual(exported["entry"][0]["resource"]["identifier"][0]["value"], patient)
            self.assertEqual(exported["entry"][1]["resource"]["valueQuantity"], {"value": 10.4, "unit": "g/dL"})


if __name__ == "__main__":
    unittest.main()
