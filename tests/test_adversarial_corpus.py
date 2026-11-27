from __future__ import annotations

import datetime as dt
import tempfile
import unittest
from pathlib import Path

from tools.adversarial_suite import generate_corpus, run_seed


class AdversarialCorpusTests(unittest.TestCase):
    def test_generated_corpus_has_no_pii_leaks_or_clinical_loss(self) -> None:
        result = run_seed(72419)
        self.assertEqual(result["pipeline_exit"], 0)
        self.assertEqual(result["pii_surface_leak_total"], 0)
        self.assertEqual(result["clinical_probes_retained"], result["clinical_probe_total"])
        self.assertEqual(result["clinician_names_preserved"], result["clinician_name_total"])
        self.assertEqual(result["stay_duration_fields_preserved"], 48)
        self.assertEqual(result["stay_duration_fields_generalized"], 0)
        self.assertEqual(result["stay_duration_exact_values_retained"], 48)
        self.assertEqual(result["stay_duration_exact_values_expected"], 48)
        self.assertTrue(result["input_unchanged"])
        self.assertEqual(result["raw_input_copies_found_in_output"], 0)
        self.assertEqual(result["temporary_artifacts_left"], 0)

    def test_varied_generator_changes_profiles_and_uses_valid_dates(self) -> None:
        with tempfile.TemporaryDirectory() as first, tempfile.TemporaryDirectory() as second:
            base = generate_corpus(Path(first), 148217)
            varied = generate_corpus(Path(second), 148217, vary_profiles=True)
        self.assertNotEqual(base["qi_profiles"], varied["qi_profiles"])
        self.assertTrue(all(dt.date.fromisoformat(row["admission_date"])
                            for row in varied["qi_profiles"]))
        self.assertGreater(len({row["district"] for row in varied["qi_profiles"]}), 1)
        self.assertGreater(len({row["diagnosis"] for row in varied["qi_profiles"]}), 1)

    def test_varied_profile_run_retains_clinical_values_and_redacts_pii(self) -> None:
        result = run_seed(148217, vary_profiles=True)
        self.assertEqual(result["pipeline_exit"], 0)
        self.assertEqual(result["pii_surface_leak_total"], 0)
        self.assertEqual(result["clinical_probes_retained"], result["clinical_probe_total"])
        self.assertEqual(result["clinician_names_preserved"], result["clinician_name_total"])


if __name__ == "__main__":
    unittest.main()
