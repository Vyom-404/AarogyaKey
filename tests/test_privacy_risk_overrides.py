from __future__ import annotations

import unittest

from src.privacy.extractor import PrivacyField, PrivacyRecord
from src.privacy.risk import _tuple


class PrivacyRiskOverrideTests(unittest.TestCase):
    def test_hospital_generalization_override_changes_release_signature(self) -> None:
        record = PrivacyRecord("site-a/record.json", "/records/0", "json", [
            PrivacyField("hospital", "Synthetic Hospital", "hospital", ("hospital",)),
        ])
        profile = ("hospital",)
        self.assertEqual(_tuple(record, profile), ("synthetic hospital",))
        actions = {(record.file, record.loc): {("hospital",): "[HOSPITAL]"}}
        self.assertEqual(_tuple(record, profile, actions), ("[hospital]",))


if __name__ == "__main__":
    unittest.main()
