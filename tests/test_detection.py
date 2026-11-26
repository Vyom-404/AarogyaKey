from __future__ import annotations

import unittest
import base64

from src.detection import PIIDetector
from src.detection.detector import field_category
from src.detection.normalization import name_keys, normalize_text, transliterate_devanagari



class NormalizationTests(unittest.TestCase):

    def test_unicode_and_hindi_digits_normalize(self) -> None:
        self.assertEqual(normalize_text("  ＡＢＣ   १२३ "), "abc 123")

    def test_common_devanagari_name_transliteration(self) -> None:
        key = " ".join(sorted(name_keys("आरव शर्मा")))
        self.assertIn("aarav sharma", key)
        self.assertIn("arav sharma", key)
        self.assertTrue(transliterate_devanagari("राहुल").startswith("raahul"))


class DetectionTests(unittest.TestCase):

    def setUp(self) -> None:
        self.detector = PIIDetector()

    def categories(self, text: str, field: str = "") -> set[str]:
        return {hit.category for hit in self.detector.find(text, field)}

    def test_indian_direct_identifiers_and_variants(self) -> None:
        cases = [
            ("Call +91 98765-43210", "PHONE"),
            ("Aadhaar: 2345 6789 0123", "AADHAAR"),
            ("ABHA ID: 12-3456-7890-1234", "ABHA_NUMBER"),
            ("UHID: HSP-26-001245", "MRN"),
            ("PAN: ABCDE1234F", "PAN"),
            ("Email: unseen.person@example.test", "EMAIL"),
        ]
        for sample, expected in cases:
            with self.subTest(category=expected):
                self.assertIn(expected, self.categories(sample))

    def test_structured_fields_are_detected(self) -> None:
        values = [
            ("Aarav Kulkarni", "Patient Name", "PATIENT_NAME"),
            ("9876543210", "mobile_no", "PHONE"),
            ("Plot 12, Lake Road", "residential_address", "ADDRESS"),
            ("226021", "postal_code", "PIN"),
            ("Kavita Verma", "guardian_name", "RELATIVE_NAME"),
        ]
        for value, field, expected in values:
            with self.subTest(field=field):
                result, hits = self.detector.sanitize(value, field)
                self.assertEqual(result, f"[{expected}]")
                self.assertEqual(hits[0].method, "structured_field")
                self.assertGreaterEqual(hits[0].confidence, 0.9)

    def test_relationship_context_and_complaint_disambiguation(self) -> None:
        self.detector.add_name("Ramesh Das", trusted=True)
        for phrase in ("S/o Zubair Khan", "D/o Nisha Patel", "W/o Kavita Rao", "C/o Ramesh Das"):
            with self.subTest(phrase=phrase):
                result, hits = self.detector.sanitize(phrase)
                self.assertIn("[RELATIVE_NAME]", result)
                self.assertTrue(any(hit.method == "relationship_context" for hit in hits))
        kept, _ = self.detector.sanitize("C/O fever and cough")
        self.assertEqual(kept, "C/O fever and cough")
        self.assertEqual(self.detector.sanitize("C/O abdominal pain")[0], "C/O abdominal pain")
        self.assertEqual(self.detector.sanitize("S/O Dengue")[0], "S/O Dengue")
        for phrase in ("Pita ji: Imran Ali", "patni: Meera Devi", "ka beta: Rohan Lal", "की बेटी: सीमा देवी"):
            with self.subTest(phrase="relationship-variant"):
                self.assertIn("[RELATIVE_NAME]", self.detector.sanitize(phrase)[0])
        for phrase in ("C/O fever", "C/O abdominal pain", "C/O dengue", "C/O bukhar"):
            with self.subTest(phrase="clinical-complaint"):
                self.assertEqual(self.detector.sanitize(phrase)[0], phrase)
        for diagnosis in ("K/C/O Bell's palsy", "K/C/O type 2 diabetes mellitus", "K/C/O chronic kidney disease"):
            with self.subTest(context="known-case-of"):
                self.assertEqual(self.detector.sanitize(diagnosis)[0], diagnosis)

    def test_location_and_policy_context_labels(self) -> None:
        for sample, category in (
            ("House: 17-B", "HOUSE"),
            ("Mohalla: Green Park", "LOCALITY"),
            ("Village: Rampur", "VILLAGE"),
            ("Landmark: near old bridge", "LANDMARK"),
            ("Policy No: POL-2026-0081", "INSURANCE_ID"),
            ("DOB: 14/03/1981", "DOB"),
        ):
            with self.subTest(category=category):
                self.assertIn(category, self.categories(sample))

    def test_indian_identity_fields_and_location_aliases(self) -> None:
        for field, category in (
            ("pmjay_id", "INSURANCE_ID"), ("hospital_uhid", "MRN"),
            ("patient_ref", "MRN"), ("accession_number", "MRN"),
            ("source_path", "METADATA"), ("Zip", "PIN"),
            ("pita_name", "RELATIVE_NAME"),
        ):
            with self.subTest(field=field):
                self.assertEqual(field_category(field), category)

    def test_name_anchors_cover_honorific_and_age_forms(self) -> None:
        for phrase in ("Asha ji 48 Y/F", "Mr. Aarav Kulkarni", "Smt. Kavita Rao"):
            with self.subTest(phrase=phrase):
                self.assertIn("PATIENT_NAME", self.categories(phrase))

    def test_report_of_name_anchor_and_clinical_negative(self) -> None:
        self.assertIn("PATIENT_NAME", self.categories("Report of Anaya Qureshi age 44/F"))
        self.assertEqual(self.detector.sanitize("Report of Dengue age 44/F")[0], "Report of Dengue age 44/F")
        self.assertIn("PATIENT_NAME", self.categories("Report of आरव शर्मा age 31/M"))

    def test_known_name_in_identifier_header_is_removed_but_schema_survives(self) -> None:
        self.detector.add_name("Anaya Qureshi", trusted=True)
        self.assertEqual(self.detector.sanitize_header_or_key("Anaya Qureshi")[0], "[PATIENT_NAME]")
        self.assertEqual(self.detector.sanitize_header_or_key("source_path")[0], "source_path")
        self.assertEqual(self.detector.sanitize_header_or_key("JJH-0077112 Zainab")[0], "[MRN] [PATIENT_NAME]")

    def test_unlabelled_compact_mrn_shape_is_detected(self) -> None:
        for value in ("ADM000161", "UHID-010565", "DHH2026-084999"):
            with self.subTest(value="compact-id"):
                self.assertIn("MRN", self.categories(value))
        self.assertEqual(self.detector.sanitize("HbA1c 123456")[0], "HbA1c 123456")

    def test_kinship_suffix_and_patient_before_relation(self) -> None:
        self.assertIn("RELATIVE_NAME", self.categories("Kamal Bhaiya called the lab"))
        self.assertIn("RELATIVE_NAME", self.categories("Jagdish Chachu: attendant"))
        self.assertIn("PATIENT_NAME", self.categories("Asha, W/o Kamal, discharged"))
        self.assertIn("PATIENT_NAME", self.categories("Patient: रीना निषाद आयु: 65 वर्ष"))
        cleaned, _ = self.detector.sanitize("नाम: रीना निषाद आयु: 65 वर्ष\nरीना निषाद को 6 दिन से बुखार है।")
        self.assertNotIn("रीना निषाद", cleaned)
        for sample in ("Reena behenji ka BP 105/77", "Kamal babu ka BP 130/82",
                       "Irfan ka BP 128/72", "Zenab Bano - K/C/O Bell's palsy"):
            with self.subTest(sample="hinglish-patient-role"):
                self.assertIn("PATIENT_NAME", self.categories(sample))
        self.assertEqual(self.detector.sanitize("Dr. Ramesh ka BP 120/80")[0], "Dr. Ramesh ka BP 120/80")

    def test_hindi_names_relationships_and_hinglish(self) -> None:
        examples = ["नाम: आरव शर्मा", "रोगी का नाम: नीलम वर्मा", "पति मोहन लाल", "Sahab ko Bukhar"]
        for value in examples[:3]:
            with self.subTest(value=value):
                result, _ = self.detector.sanitize(value)
                self.assertIn("[", result)
        self.assertEqual(self.detector.sanitize(examples[3])[0], examples[3])

    def test_name_lexicon_finds_new_name_and_transliteration(self) -> None:
        self.detector.add_name("आरव शर्मा")
        latin_result, latin_hits = self.detector.sanitize("Patient seen: Aarav Sharma")
        hindi_result, hindi_hits = self.detector.sanitize("रोगी आरव शर्मा को देखा")
        ambiguous_result, _ = self.detector.sanitize("आज आरव शर्मा आए")
        self.assertIn("[PATIENT_NAME]", latin_result)
        self.assertIn("[PATIENT_NAME]", hindi_result)
        self.assertEqual(ambiguous_result, "आज आरव शर्मा आए")
        self.assertTrue(any(hit.method in {"identity_label", "contextual_name_lexicon"} for hit in latin_hits + hindi_hits))
