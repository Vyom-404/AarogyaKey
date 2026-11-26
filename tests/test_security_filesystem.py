from __future__ import annotations

import hashlib
import os
import stat
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.pipeline import UnsafeInput, _private_directory, _private_write, _safe_output_path, run_pipeline

SECRET = "unit test security secret 2026"


class FilesystemHardeningTests(unittest.TestCase):
    def test_output_modes_and_no_temporary_artifacts(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "input"
            output = root / "output"
            source.mkdir()
            (source / "patients.csv").write_text(
                "patient_name,mrn,dob\nSynthetic Person,MR-552,1982-04-03\n", encoding="utf-8"
            )
            report = run_pipeline(source, output, SECRET)
            self.assertEqual(report["counts"]["files_sanitized"], 1)
            self.assertEqual(stat.S_IMODE(output.stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((output / "sanitized").stat().st_mode), 0o700)
            self.assertEqual(stat.S_IMODE((output / "report.json").stat().st_mode), 0o600)
            self.assertFalse(any(path.name.endswith(".tmp") for path in output.rglob("*")))
            exported = b"".join(path.read_bytes() for path in output.rglob("*") if path.is_file())
            self.assertNotIn(b"Synthetic Person", exported)
            self.assertNotIn(SECRET.encode(), exported)
            self.assertFalse((output / "identity_map.json").exists())

    def test_failed_atomic_write_cleans_its_temporary_file(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            path = Path(temp) / "result.json"
            with patch("src.pipeline.os.replace", side_effect=OSError("synthetic failure")):
                with self.assertRaises(OSError):
                    _private_write(path, "sanitized")
            self.assertFalse(path.exists())
            self.assertEqual(list(Path(temp).iterdir()), [])

    def test_path_traversal_and_symlinked_output_parent_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            outside = root / "outside"
            outside.mkdir()
            with self.assertRaisesRegex(UnsafeInput, "unsafe_output_path"):
                _safe_output_path(root, "../outside/file.txt")
            (root / "linked").symlink_to(outside, target_is_directory=True)
            with self.assertRaisesRegex(OSError, "private_directory_unavailable"):
                _private_directory(root / "linked" / "nested")
            self.assertFalse((outside / "nested").exists())

    def test_output_symlink_and_overlapping_roots_are_rejected(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source = root / "input"
            source.mkdir()
            target = root / "other"
            target.mkdir()
            link = root / "output-link"
            link.symlink_to(target, target_is_directory=True)
            with self.assertRaisesRegex(ValueError, "output_path_unsafe"):
                run_pipeline(source, link, SECRET)
            with self.assertRaisesRegex(ValueError, "outside_input"):
                run_pipeline(source, root, SECRET)

    def test_oversized_input_is_quarantined_and_hash_is_accurate(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output = root / "input", root / "output"
            source.mkdir()
            body = b"patient_name\nSynthetic Person\n"
            (source / "large.csv").write_bytes(body)
            report = run_pipeline(source, output, SECRET, {"max_file_bytes": 8})
            item = report["files"][0]
            self.assertEqual(item["status"], "quarantined")
            self.assertEqual(item["input_sha256"], hashlib.sha256(body).hexdigest())
            self.assertFalse((output / "sanitized/large.csv").exists())

    def test_symlink_directory_is_not_traversed_or_exported(self) -> None:
        with tempfile.TemporaryDirectory() as temp:
            root = Path(temp)
            source, output, outside = root / "input", root / "output", root / "outside"
            source.mkdir()
            outside.mkdir()
            (outside / "private.txt").write_text("Synthetic Person", encoding="utf-8")
            (source / "linked-directory").symlink_to(outside, target_is_directory=True)
            report = run_pipeline(source, output, SECRET)
            self.assertEqual(report["counts"]["files_total"], 1)
            self.assertEqual(report["counts"]["files_quarantined"], 1)
            self.assertFalse((output / "sanitized/linked-directory/private.txt").exists())
