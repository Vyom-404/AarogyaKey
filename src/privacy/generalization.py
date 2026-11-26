"""Truthful age and length-of-stay generalization helpers."""

from __future__ import annotations

import re


def parse_age(value: object) -> tuple[int, str] | None:
    """Return (age, suffix) for an explicit age form, never a duration."""
    if isinstance(value, bool) or value is None:
        return None
    if isinstance(value, int):
        return (value, "") if 0 <= value <= 120 else None
    text = str(value).strip()
    match = re.fullmatch(r"\s*(\d{1,3})(?:\s*(?:years?|yrs?|y|वर्ष|साल))?(?:\s*[/,| -]\s*([MFmf]))?\s*", text)
    if not match:
        return None
    age = int(match.group(1))
    if not 0 <= age <= 120:
        return None
    return age, ("/" + match.group(2).upper() if match.group(2) else "")


def age_band(age: int, width: int = 5, senior_from: int = 85, minor_boundaries: tuple[int, ...] = (0, 5, 10, 15, 18)) -> str:
    if not 0 <= age <= 120 or width < 2 or senior_from < 65:
        raise ValueError("invalid_age_band_input")
    if age >= senior_from:
        return f"{senior_from}+"
    for lower, upper in zip(minor_boundaries, minor_boundaries[1:]):
        if lower <= age < upper:
            return f"{lower}-{upper - 1}"
    adult_start = minor_boundaries[-1] if minor_boundaries and minor_boundaries[-1] == 18 else 18
    if adult_start <= age < 20:
        return f"{adult_start}-19"
    lower = (age // width) * width
    upper = min(lower + width - 1, senior_from - 1)
    return f"{lower}-{upper}"


def generalize_age(value: object, width: int = 5, senior_from: int = 85,
                   minor_boundaries: tuple[int, ...] = (0, 5, 10, 15, 18)) -> str | None:
    parsed = parse_age(value)
    if parsed is None:
        return None
    age, suffix = parsed
    return age_band(age, width, senior_from, minor_boundaries) + suffix
