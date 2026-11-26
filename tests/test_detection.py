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
