"""Structured logging with an allowlist of privacy-safe fields."""

from __future__ import annotations

import json
import logging
import re

_SAFE_FIELDS = frozenset({"file_sha256", "status", "reason", "records", "stage"})


def log_event(logger: logging.Logger, event: str, **fields: object) -> None:
    """Emit one JSON event, dropping fields that could contain raw input."""
    safe: dict[str, object] = {"event": event if event in {"file_processed"} else "operation"}
    for key, value in fields.items():
        if key not in _SAFE_FIELDS:
            continue
        if key == "file_sha256":
            if isinstance(value, str) and re.fullmatch(r"[0-9a-f]{64}", value):
                safe[key] = value
        elif key in {"status", "reason", "stage"}:
            if isinstance(value, str) and re.fullmatch(r"[a-z0-9_]{1,64}", value):
                safe[key] = value
        elif key == "records" and isinstance(value, int) and value >= 0:
            safe[key] = value
    logger.info("%s", json.dumps(safe, sort_keys=True, separators=(",", ":")))
