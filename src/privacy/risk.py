"""Aggregate record-level equivalence-class measurements without raw values."""

from __future__ import annotations

import re
import statistics
from collections import Counter
from typing import Any

from src.detection.normalization import normalize_text
from src.privacy.date_shifter import parse_date
from src.privacy.extractor import PrivacyRecord
from src.privacy.generalization import age_band, generalize_stay, parse_age


def _feature(record: PrivacyRecord, kind: str, actions: dict[tuple[str | int, ...], str] | None = None) -> str:
    actions = actions or {}
    values: list[str] = []
    for item in record.fields:
        if item.kind != ("event_date" if kind == "event_date_exact" else kind):
            continue
        value = actions.get(item.path, item.value)
        normalized = normalize_text(str(value))
        if normalized and normalized not in {"[village]", "[locality]", "[address]", "[pin]", "[house]", "[landmark]", ""}:
            values.append(normalized)
    if kind == "age" and values:
        parsed = parse_age(values[0])
        if parsed:
            values[0] = str(parsed[0])
        else:
            match = re.fullmatch(r"(\d{1,3})-(\d{1,3})(?:/([mf]))?", values[0])
            if match:
                values[0] = f"{match.group(1)}-{match.group(2)}"
    if kind == "event_date_exact" and values:
        pass
    elif kind == "event_date" and values:
        values = [parse_date(value).value.strftime("%Y-%m") if parse_date(value) else value[:7]
                  for value in values]
    return "|".join(sorted(set(values)))


def _hospital(record: PrivacyRecord) -> str:
    explicit = _feature(record, "hospital")
    if explicit:
        return explicit
    parts = record.file.split("/")
    return normalize_text(parts[0]) if len(parts) > 1 else "unknown"


def _tuple(record: PrivacyRecord, dimensions: tuple[str, ...],
           actions: dict[tuple[str, int | str], dict[tuple[str | int, ...], str]] | None = None) -> tuple[str, ...]:
    override = (actions or {}).get((record.file, record.loc), {})
    values = []
    for dimension in dimensions:
        value = _hospital(record) if dimension == "hospital" else _feature(record, dimension, override)
        values.append(value or "<missing>")
    return tuple(values)


def _class_stats(records: list[PrivacyRecord], dimensions: tuple[str, ...],
                 actions: dict[tuple[str, str], dict[tuple[str | int, ...], str]] | None = None,
                 minimum_k: int = 3) -> dict[str, Any]:
    groups = Counter(_tuple(record, dimensions, actions) for record in records)
    sizes = [groups[_tuple(record, dimensions, actions)] for record in records]
    singleton_records = sum(size == 1 for size in sizes)
    return {
        "records": len(records),
        "equivalence_classes": len(groups),
        "unique_records": singleton_records,
        "unique_record_percent": round(100 * singleton_records / len(records), 2) if records else 0.0,
        "below_k_records": sum(size < minimum_k for size in sizes),
        "minimum_class_size": min(groups.values()) if groups else 0,
        "median_class_size": round(float(statistics.median(groups.values())), 2) if groups else 0.0,
        "class_size_histogram": {
            "1": sum(size == 1 for size in groups.values()),
            "2": sum(size == 2 for size in groups.values()),
            "3_to_4": sum(3 <= size <= 4 for size in groups.values()),
            "5_plus": sum(size >= 5 for size in groups.values()),
        },
    }
