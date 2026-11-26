from __future__ import annotations

import unittest

from src.detection import PIIDetector


class AdversarialClinicalPreservationTests(unittest.TestCase):
    def test_procedure_and_ambiguous_clinical_phrases_are_preserved(self) -> None:
        detector = PIIDetector()
        for phrase in ("Appendectomy", "C/O abdominal pain", "K/C/O Bell's palsy"):
            with self.subTest(phrase=phrase):
                self.assertEqual(detector.sanitize(phrase)[0], phrase)

    def test_length_of_stay_schema_keys_are_not_classified_as_names(self) -> None:
        detector = PIIDetector()
        for key in ("stay_duration", "length_of_stay", "hospital_stay"):
            with self.subTest(key=key):
                self.assertEqual(detector.sanitize_header_or_key(key), (key, []))
        self.assertEqual(detector.sanitize_header_or_key("Nivaan Doren")[0], "[PATIENT_NAME]")


if __name__ == "__main__":
    unittest.main()
