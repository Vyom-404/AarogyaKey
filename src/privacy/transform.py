"""Plan deterministic, locator-aware privacy transformations."""

from __future__ import annotations

import re
from collections import Counter, defaultdict
from typing import Any

from src.detection.normalization import normalize_text
from src.privacy.date_shifter import DateShifter, format_date, month_precision, parse_date
from src.privacy.extractor import PrivacyAction, PrivacyField, PrivacyRecord
from src.privacy.generalization import age_band, generalize_age, generalize_stay
from src.privacy.risk import _feature, _tuple


def _marker(field: PrivacyField) -> str:
    normalized = re.sub(r"[^a-z]+", "", field.field_name.casefold())
    if field.kind == "pin":
        return "[PIN]"
    if field.kind == "locality":
        return "[LOCALITY]" if any(x in normalized for x in ("mohalla", "locality", "ward", "town", "city")) else "[VILLAGE]"
    if field.kind == "address_detail":
        return "[LANDMARK]" if "landmark" in normalized else "[HOUSE]"
    if field.kind == "address":
        return "[ADDRESS]"
    return ""


def _replacement_for_date(value: str, patient: str | None, shifter: DateShifter,
                         unresolved_precision: str = "month") -> str | None:
    parsed = parse_date(value)
    if parsed is None:
        return None
    if patient:
        return format_date(shifter.shift(parsed.value, patient), parsed, value)
    if unresolved_precision == "year":
        return parsed.value.strftime("%Y")
    return month_precision(value)


def _rare_diagnosis_replacement(value: str) -> str:
    text = value.strip()
    code = re.fullmatch(r"([A-TV-Z]\d{2})(?:\.\w+)?", text, re.I)
    if code:
        return code.group(1).upper()
    # Free-text concepts have no safe ontology-backed broader concept here.
    # Preserve them rather than replacing clinically meaningful text blindly.
    return ""


def build_privacy_actions(records: list[PrivacyRecord], pseudonyms: dict[tuple[str, str], str],
                          secret: str, policy: dict[str, Any] | None = None) -> dict[tuple[str, str], list[PrivacyAction]]:
    policy = policy or {}
    width = int(policy.get("age_band_years", 5))
    senior_from = int(policy.get("senior_age_from", 85))
    minor_bounds = tuple(int(part) for part in str(policy.get("minor_age_boundaries", "0,5,10,15,18")).split(","))
    shift_days = int(policy.get("date_shift_max_days", 365))
    unresolved_precision = str(policy.get("unresolved_date_precision", "month")).casefold()
    if unresolved_precision not in {"month", "year"}:
        raise ValueError("unresolved_date_precision_is_invalid")
    pin_digits = int(policy.get("pin_prefix_digits", 3))
    minimum_k = int(policy.get("minimum_equivalence_class", 3))
    rare_count_max = int(policy.get("rare_diagnosis_max_count", 2))
    rare_diagnosis_action = str(policy.get("rare_diagnosis_action", "preserve")).casefold()
    shifter = DateShifter(secret, shift_days)
    grouped: dict[tuple[str, str], list[PrivacyAction]] = defaultdict(list)
    record_by_ref = {(item.file, item.loc): item for item in records}
    diagnosis_counts = Counter(
        normalize_text(field.value) for item in records for field in item.fields
        if field.kind == "diagnosis"
    )
    action_values: dict[tuple[str, str], dict[tuple[str | int, ...], str]] = defaultdict(dict)
    action_by_field: dict[tuple[str, str, tuple[str | int, ...], str], PrivacyAction] = {}

    for item in records:
        ref = (item.file, item.loc)
        patient = pseudonyms.get(ref)
        parents = {field.kind: field.value for field in item.fields if field.kind in {"tehsil", "district", "state"}}
        coarse = next(((level, parents[level]) for level in ("tehsil", "district", "state") if parents.get(level)), None)
        marker_counts: Counter[str] = Counter()
        for field in item.fields:
            replacement: str | None = None
            action = ""
            stage = "after"
            marker = ""
            if field.kind == "event_date":
                replacement = _replacement_for_date(field.value, patient, shifter, unresolved_precision)
                if replacement is None or replacement == field.value:
                    continue
                action = "shifted_date" if patient else "generalized_date"
                stage = "before"
            elif field.kind == "age":
                replacement = generalize_age(field.value, width, senior_from, minor_bounds)
                if replacement is None or replacement == field.value:
                    continue
                action, stage = "generalized_age", "before"
            elif field.kind in {"locality", "address", "address_detail"}:
                # Hospital ward labels describe care location, not residence.
                # They are retained as clinical context; residential ward
                # identifiers in address fields remain handled by the PII layer.
                if field.kind == "locality" and re.fullmatch(r"\d{1,2}\s*\(Medicine\)", field.value, re.I):
                    continue
                if field.kind == "locality" and field.field_name.casefold() == "ward":
                    if "wards" in {str(part).casefold() for part in field.path}:
                        continue
                marker = _marker(field)
                if field.kind == "locality" and coarse:
                    level, value = coarse
                    replacement = f"{level.capitalize()}-level location: {value}"
                    action = "generalized_location"
                else:
                    replacement = ""
                    action = "suppressed_location"
                stage = "before"
            elif field.kind == "pin":
                digits = re.sub(r"\D", "", field.value)
                if len(digits) >= 6:
                    is_fhir_address = item.file_format == "json" and any(
                        isinstance(part, str) and part.casefold() == "address" for part in field.path
                    )
                    replacement = _marker(field) if is_fhir_address else digits[:pin_digits] + "***"
                    action = "suppressed_pin" if is_fhir_address else "generalized_pin"
                    marker = _marker(field) if is_fhir_address else ""
                    stage = "before"
                else:
                    continue
            elif field.kind == "dob":
                # Phase 2 already suppresses exact DOB values. This action is
                # counted only when a visible source DOB anchor is present.
                marker = "[DOB]"
                replacement = marker
                action = "suppressed_dob"
            if replacement is None or not action:
                continue
            marker_index = marker_counts[marker] if marker else 0
            if marker:
                marker_counts[marker] += 1
            planned = PrivacyAction(item.file, item.loc, field.kind, field.path, replacement,
                                    action, marker, marker_index, field.span, stage)
            grouped[ref].append(planned)
            action_by_field[(item.file, item.loc, field.path, field.kind)] = planned
            if field.path:
                action_values[ref][field.path] = replacement

    return {ref: actions for ref, actions in grouped.items()}
