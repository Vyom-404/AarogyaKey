"""Small standard-library policy loader."""

from __future__ import annotations

from pathlib import Path


def load_policy(path: Path) -> dict[str, int | str]:
    """Load simple ``key: scalar`` policy entries without a YAML dependency."""
    policy: dict[str, int | str] = {}
    if not path.exists():
        return policy
    for raw_line in path.read_text(encoding="utf-8").splitlines():
        line = raw_line.split("#", 1)[0].strip()
        if not line or ":" not in line:
            continue
        key, value = (part.strip() for part in line.split(":", 1))
        if not key:
            continue
        policy[key] = int(value) if value.lstrip("-").isdigit() else value.strip("'\"")
    return policy

