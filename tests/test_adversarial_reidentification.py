from __future__ import annotations

import unittest

from tools.adversarial_suite import run_seed


class AdversarialReidentificationTests(unittest.TestCase):
    def test_generalized_records_reduce_auxiliary_unique_matches(self) -> None:
        attack = run_seed(72419)["auxiliary_registry_attack"]
        self.assertGreater(attack["mean_candidate_count_released"], 0)
        self.assertLessEqual(attack["released_unique_match_percent"], attack["raw_unique_match_percent"])
        self.assertEqual(attack["exact_known_admission_date_matches_after_shift"], 0)


if __name__ == "__main__":
    unittest.main()
