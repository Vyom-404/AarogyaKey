from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.privacy import DateShifter, age_band, build_privacy_actions, collect_privacy_records, equivalence_summary
from src.privacy.date_shifter import format_date, month_precision, parse_date
from src.privacy.extractor import PrivacyRecord
from src.pipeline import run_pipeline


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


