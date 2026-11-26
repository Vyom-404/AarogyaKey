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

    def test_us_month_first_dates_are_parsed_only_when_day_month_is_invalid(self) -> None:
        parsed = parse_date("03/23/2026")
        self.assertIsNotNone(parsed)
        self.assertEqual(parsed.format_name, "%m/%d/%Y")
        self.assertEqual(month_precision("03/23/2026"), "03/2026")
        self.assertEqual(month_precision("23/03/2026"), "03/2026")
        shifter = DateShifter("phase4 deterministic test secret")
        shifted = shifter.shift(parsed.value, "PSN-AAA")
        exported = format_date(shifted, parsed, "03/23/2026")
        self.assertEqual(parse_date(exported).value.date(), shifted.date())
        self.assertRegex(exported, r"^\d{4}-\d{2}-\d{2}$")

    def test_month_only_values_have_stable_canonical_month_keys(self) -> None:
        from src.privacy.risk import _month_key

        self.assertEqual(_month_key("03/2026"), "2026-03")
        self.assertEqual(_month_key("2026-03"), "2026-03")
        self.assertEqual(_month_key("March 2026"), "2026-03")

    def test_unresolved_dates_keep_month_and_remove_exact_day(self) -> None:
        self.assertEqual(month_precision("2025-09-17"), "2025-09")
        self.assertEqual(month_precision("17/09/2025"), "09/2025")
        record = PrivacyRecord("hospital/unresolved.csv", "row:0", "csv")
        record.add("event_date", "2025-09-17", "visit_date", (0,))
        actions = build_privacy_actions([record], {}, "phase4 deterministic test secret",
                                        {"unresolved_date_precision": "year"})
        self.assertEqual(actions[(record.file, record.loc)][0].replacement, "2025")


