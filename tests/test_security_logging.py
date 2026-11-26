from __future__ import annotations

import io
import logging
import os
import unittest
from unittest.mock import patch

from src.pipeline import main
from src.security.safe_logging import log_event

SECRET = "unit test security secret 2026"


class PrivacySafeLoggingTests(unittest.TestCase):
    def test_structured_log_drops_unapproved_sensitive_fields(self) -> None:
        logger = logging.getLogger("test.security.safe-log")
        logger.setLevel(logging.INFO)
        output = io.StringIO()
        handler = logging.StreamHandler(output)
        logger.addHandler(handler)
        try:
            log_event(logger, "record_done", file_sha256="a" * 64, status="sanitized",
                      patient_name="Synthetic Person", raw="PRIVATE NOTE", secret=SECRET,
                      reason="Synthetic Person is the failure")
        finally:
            logger.removeHandler(handler)
        rendered = output.getvalue()
        self.assertIn('"event":"operation"', rendered)
        self.assertIn('"file_sha256"', rendered)
        self.assertNotIn("Synthetic Person", rendered)
        self.assertNotIn("PRIVATE NOTE", rendered)
        self.assertNotIn(SECRET, rendered)
        self.assertNotIn("Synthetic Person", rendered)

    def test_invalid_secret_error_does_not_echo_secret(self) -> None:
        stderr = io.StringIO()
        with patch.dict(os.environ, {"RAKSHA_SECRET": "weak secret"}), patch("sys.stderr", stderr):
            code = main(["--input", "/synthetic/private/path", "--output", "/tmp/phase5-error"])
        self.assertEqual(code, 2)
        self.assertNotIn("weak secret", stderr.getvalue())
        self.assertIn("processing_failed", stderr.getvalue())
