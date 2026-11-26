from __future__ import annotations

import unittest

from src.detection import PIIDetector


class AdversarialClinicalPreservationTests(unittest.TestCase):
    def test_procedure_and_ambiguous_clinical_phrases_are_preserved(self) -> None:
        detector = PIIDetector()
        for phrase in ("Appendectomy", "C/O abdominal pain", "K/C/O Bell's palsy"):
            with self.subTest(phrase=phrase):
                self.assertEqual(detector.sanitize(phrase)[0], phrase)


if __name__ == "__main__":
    unittest.main()
