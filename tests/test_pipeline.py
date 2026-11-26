from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from src.pipeline import run_pipeline



class PipelineTests(unittest.TestCase):

    def setUp(self) -> None:
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.inp = self.root / "input"
        self.out = self.root / "output"
        self.inp.mkdir()

    def tearDown(self) -> None:
        self.temp.cleanup()

    def run_it(self) -> dict:
        return run_pipeline(self.inp, self.out, "unit-test-secret", {"max_json_depth": 20})

    def test_csv_text_and_row_locations(self) -> None:
        (self.inp / "records.csv").write_text("name,value\nExample,5 mg\n", encoding="utf-8")
        report = self.run_it()
        self.assertEqual(report["counts"]["files_sanitized"], 1)
        self.assertEqual((self.out / "sanitized/records.csv").read_text(), "name,value\n[PATIENT_NAME],5 mg\n")
        records = [json.loads(line) for line in (self.out / "records.jsonl").read_text().splitlines()]
        self.assertEqual(records, [{"file": "sanitized/records.csv", "loc": "row:0", "patient": None}])

    def test_nested_json_pointer_and_fhir_document_location(self) -> None:
        (self.inp / "visits.json").write_text('{"visits":[{"x":1},{"x":2}]}', encoding="utf-8")
        (self.inp / "bundle.json").write_text(
            '{"resourceType":"Bundle","type":"collection","entry":[]}', encoding="utf-8"
        )
        self.run_it()
        records = [json.loads(line) for line in (self.out / "records.jsonl").read_text().splitlines()]
        self.assertIn({"file": "sanitized/visits.json", "loc": "/visits/1", "patient": None}, records)
        self.assertIn({"file": "sanitized/bundle.json", "loc": "doc", "patient": None}, records)
