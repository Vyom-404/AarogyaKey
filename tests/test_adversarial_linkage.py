from __future__ import annotations

import unittest

from tools.adversarial_suite import linkage_scenarios


class AdversarialLinkageTests(unittest.TestCase):
    def test_scenario_metrics_prioritize_zero_false_merges(self) -> None:
        results = linkage_scenarios(72419)
        for label, metrics in results.items():
            with self.subTest(scenario=label):
                self.assertEqual(metrics["false_merges"], 0)
        self.assertEqual(results["cross_hospital_cross_script_strong_id"]["recall"], 1.0)
        self.assertEqual(results["name_only_weak_evidence"]["unresolved_records"], 2)


if __name__ == "__main__":
    unittest.main()
