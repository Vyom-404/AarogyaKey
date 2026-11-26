from __future__ import annotations

import unittest

from tools.adversarial_suite import run_seed


class AdversarialCorpusTests(unittest.TestCase):
    def test_generated_corpus_has_no_pii_leaks_or_clinical_loss(self) -> None:
        result = run_seed(72419)
        self.assertEqual(result["pipeline_exit"], 0)
        self.assertEqual(result["pii_surface_leak_total"], 0)
        self.assertEqual(result["clinical_probes_retained"], result["clinical_probe_total"])
        self.assertEqual(result["clinician_names_preserved"], result["clinician_name_total"])
        self.assertTrue(result["input_unchanged"])
        self.assertEqual(result["raw_input_copies_found_in_output"], 0)
        self.assertEqual(result["temporary_artifacts_left"], 0)


if __name__ == "__main__":
    unittest.main()
