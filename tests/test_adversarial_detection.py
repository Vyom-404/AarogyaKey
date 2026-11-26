from __future__ import annotations

import unittest

from src.detection import PIIDetector


class AdversarialDetectionTests(unittest.TestCase):
    def test_devanagari_patient_and_clinical_abbreviations(self) -> None:
        detector = PIIDetector()
        source = "सिंथेटिका बेन्द्रे को आज जांचा गया; C/O fever; K/C/O diabetes."
        cleaned, hits = detector.sanitize(source)
        self.assertNotIn("सिंथेटिका बेन्द्रे", cleaned)
        self.assertIn("[PATIENT_NAME]", cleaned)
        self.assertIn("C/O fever", cleaned)
        self.assertIn("K/C/O diabetes", cleaned)
        self.assertTrue(any(hit.category == "PATIENT_NAME" for hit in hits))

    def test_relative_name_is_removed_with_relationship_context(self) -> None:
        cleaned, hits = PIIDetector().sanitize("S/o: Nivaan Doren")
        self.assertNotIn("Nivaan Doren", cleaned)
        self.assertTrue(any(hit.category == "RELATIVE_NAME" for hit in hits))


if __name__ == "__main__":
    unittest.main()
