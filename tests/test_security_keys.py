from __future__ import annotations

import unittest

from src.linkage.pseudonymizer import Pseudonymizer
from src.privacy.date_shifter import DateShifter
from src.security.secret_manager import SecretManager, derive_key

SECRET = "unit test security secret 2026"


class KeyManagementTests(unittest.TestCase):
    def test_missing_blank_and_weak_secrets_fail_closed(self) -> None:
        for secret in ("", "             ", "short", "123456789012345"):
            with self.subTest(secret_length=len(secret)):
                with self.assertRaises(ValueError):
                    SecretManager(secret)
        with self.assertRaises(ValueError):
            Pseudonymizer("")
        with self.assertRaises(ValueError):
            DateShifter("short")

    def test_purpose_keys_are_separated_and_secret_rotation_changes_them(self) -> None:
        manager = SecretManager(SECRET)
        pseudonym_key = manager.key_for("patient-pseudonym/v2")
        date_key = manager.key_for("date-shift/v2")
        encryption_key = manager.key_for("intermediate-aead/v1")
        self.assertEqual(len({pseudonym_key, date_key, encryption_key}), 3)
        self.assertNotEqual(pseudonym_key, derive_key("rotated unit security secret 2026", "patient-pseudonym/v2"))
        with self.assertRaisesRegex(ValueError, "key_purpose_invalid"):
            manager.key_for("unknown")
        self.assertNotIn(SECRET, repr(manager))

    def test_rotated_secret_changes_pseudonyms_and_date_offsets(self) -> None:
        anchor = ("mrn", "site-a", "MR-552")
        first = Pseudonymizer(SECRET).pseudonym(anchor)
        second = Pseudonymizer("rotated unit security secret 2026").pseudonym(anchor)
        self.assertNotEqual(first, second)
        offset_a = DateShifter(SECRET).offset_days("PSN-UNIT-A")
        offset_b = DateShifter("rotated unit security secret 2026").offset_days("PSN-UNIT-A")
        self.assertNotEqual(offset_a, offset_b)
