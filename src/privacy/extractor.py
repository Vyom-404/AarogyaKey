"""Extract quasi-identifier fields and safe transformation paths in memory."""

from __future__ import annotations

import csv
import datetime as dt
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.linkage.extractor import decode_input
from src.privacy.date_shifter import parse_date

SUPPORTED = {".csv", ".tsv", ".json", ".txt"}
_EVENT_DATE_KEYS = {
    "createdat", "updatedat", "createdon", "updatedon", "exportedat", "timestamp", "timestamputc",
    "recorded", "recordedat", "effective", "effectiveat", "performed", "performedat", "onset",
    "lastupdated", "lastupdatedat",
}
_AGE_KEY = re.compile(r"^(?:age|patientage|age_sex|ageyears|umar|वय|आयु|उम्र)$", re.I)
_DATE_VALUE = re.compile(
    r"(?<![\w/])(?:\d{4}-\d{1,2}-\d{1,2}(?:[T ][0-9:.+-]+Z?)?|\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})(?![\w/])"
)
_MONTH_VALUE = re.compile(r"(?<![\w/])(?:\d{4}[-/]\d{1,2}|\d{1,2}[./-]\d{4}|[A-Za-z]{3,9}\s+\d{4}|\d{4})(?![\w/])", re.I)


@dataclass(frozen=True, repr=False)
class PrivacyField:
    kind: str
    value: str
    field_name: str
    path: tuple[str | int, ...] = ()
    span: tuple[int, int] | None = None


@dataclass(repr=False)
class PrivacyRecord:
    file: str
    loc: str
    file_format: str
    fields: list[PrivacyField] = field(default_factory=list)

    def add(self, kind: str, value: Any, field_name: str, path: tuple[str | int, ...] = (),
            span: tuple[int, int] | None = None) -> None:
        if value is None or isinstance(value, (dict, list, bool)):
            return
        text = str(value).strip()
        if not text or text.casefold() in {"null", "none", "unknown", "na", "n/a", "-"}:
            return
        self.fields.append(PrivacyField(kind, text, field_name, path, span))


@dataclass(frozen=True, repr=False)
class PrivacyAction:
    file: str
    loc: str
    kind: str
    path: tuple[str | int, ...]
    replacement: str
    action: str
    marker: str = ""
    marker_index: int = 0
    span: tuple[int, int] | None = None
    stage: str = "after"


def _key_kind(key: str, parent: str = "") -> str | None:
    normalized = re.sub(r"[^a-z0-9]+", "", key.casefold())
    parent_n = re.sub(r"[^a-z0-9]+", "", parent.casefold())
    if _AGE_KEY.fullmatch(normalized):
        return "age"
    if normalized in {"birthdate", "dateofbirth", "dob", "janmtithi"}:
        return "dob"
    if normalized in _EVENT_DATE_KEYS:
        return "event_date"
    if normalized.startswith("date") or normalized.endswith(("date", "datetime")) or (normalized in {"start", "end"} and "encounterperiod" in parent_n):
        return "event_date"
    if normalized in {"house", "houseno", "housenumber", "street", "line", "landmark", "premise", "flat", "addressline"}:
        return "address_detail"
    if normalized in {"address", "addressnote", "patientaddress"}:
        return "address"
    if normalized in {"village", "gaon", "gram", "mohalla", "locality", "ward", "block"}:
        return "locality"
    if normalized in {"tehsil", "taluka", "subdistrict"}:
        return "tehsil"
    if normalized in {"district", "jila", "jilha"}:
        return "district"
    if normalized in {"state", "province"}:
        return "state"
    if normalized in {"pin", "pincode", "postalcode", "zipcode", "zip"}:
        return "pin"
    if normalized in {"lengthofstay", "los", "stayduration", "hospitalstay", "hospitalduration", "staydays"}:
        return "stay"
    if "diagnos" in normalized or normalized in {"conditionname", "icd", "icdcode", "clinicalimpression"}:
        return "diagnosis"
    if "conditioncode" in parent_n and normalized in {"text", "display", "code"}:
        return "diagnosis"
    if normalized in {"hospital", "hospitalname", "facility", "facilityname"}:
        return "hospital"
    if "period" in parent_n and normalized in {"start", "end"}:
        return "event_date"
    return None


def _record_roots(data: Any, rel: str) -> list[tuple[str, tuple[str | int, ...], Any]]:
    if isinstance(data, dict) and str(data.get("resourceType", "")).casefold() == "bundle":
        return [("doc", (), data)]
    records: list[tuple[str, tuple[str | int, ...], Any]] = []
    if isinstance(data, dict):
        for key, value in data.items():
            if isinstance(value, list) and value and all(isinstance(item, dict) for item in value):
                escaped = str(key).replace("~", "~0").replace("/", "~1")
                records.extend((f"/{escaped}/{index}", (str(key), index), item)
                               for index, item in enumerate(value))
    return records or [("doc", (), data)]


def _walk_json(record: PrivacyRecord, node: Any, path: tuple[str | int, ...] = (), parent: str = "",
               resource_type: str = "") -> None:
    if isinstance(node, dict):
        rt = str(node.get("resourceType", resource_type)).casefold()
        for key, child in node.items():
            key_s = str(key)
            child_path = path + (key_s,)
            context = (parent + " " + key_s).strip()
            kind = _key_kind(key_s, parent)
            if kind is None and isinstance(child, str) and parse_date(child):
                # Strict full-date parsing also catches date values stored in
                # loosely named metadata keys without matching arbitrary text.
                kind = "event_date"
            if rt == "encounter" and key_s.casefold() == "period":
                context += " encounterperiod"
            if rt == "condition" and key_s.casefold() == "code":
                context += " conditioncode"
            if kind:
                if isinstance(child, (str, int, float)):
                    record.add(kind, child, key_s, child_path)
                elif isinstance(child, (dict, list)) and kind in {"address", "stay"}:
                    _walk_json(record, child, child_path, context, rt)
                    continue
            if isinstance(child, (dict, list)):
                _walk_json(record, child, child_path, context, rt)
    elif isinstance(node, list):
        for index, child in enumerate(node):
            _walk_json(record, child, path + (index,), parent, resource_type)


def _text_fields(record: PrivacyRecord, text: str) -> None:
    label_patterns = {
        "dob": r"(?:date\s+of\s+birth|dob|birth\s+date|जन्म\s*तिथि|जन्म\s*दिनांक)",
        "event_date": r"(?:date\s+of\s+(?:admission|discharge)|admission\s+date|discharge\s+date|visit\s+date|encounter\s+date|reg\s+date|date(?!\s+of\s+birth)|दिनांक|तारीख)",
        "age": r"(?:patient\s+age|age|umar|आयु|उम्र|वय)",
        "locality": r"(?:village|gaon|gram|mohalla|locality|ward|गांव|गाँव|ग्राम)",
        "tehsil": r"(?:tehsil|taluka|तहसील)",
        "district": r"(?:district|jila|zilla|जिला)",
        "pin": r"(?:pin(?:\s*code)?|postal\s*code|pincode)",
        "address": r"(?:address|residence|पता)",
        "address_detail": r"(?:house\s*(?:no|number)?|street|landmark|mohalla\s*address)",
        "diagnosis": r"(?:diagnosis|assessment|clinical\s+impression|dx|निदान)",
        "stay": r"(?:length\s+of\s+stay|stay\s+duration|hospital\s+stay|los)",
    }
    for kind, label in label_patterns.items():
        pattern = re.compile(rf"(?im)^\s*{label}\s*[:=#-]\s*([^\n;|]+)")
        for match in pattern.finditer(text):
            start, end = match.span(1)
            raw = match.group(1).strip().rstrip(",")
            left = start + (len(match.group(1)) - len(match.group(1).lstrip()))
            right = left + len(raw)
            if kind in {"event_date", "dob"}:
                date_match = next((candidate for candidate in _DATE_VALUE.finditer(raw)
                                   if parse_date(candidate.group())), None)
                if date_match is None and kind == "event_date":
                    date_match = next((candidate for candidate in _MONTH_VALUE.finditer(raw)
                                       if _valid_month_value(candidate.group())), None)
                if not date_match:
                    continue
                left += date_match.start()
                right = left + len(date_match.group())
                raw = date_match.group()
            record.add(kind, raw, kind, (f"@{left}:{right}",), (left, right))


def _valid_month_value(value: str) -> bool:
    text = value.strip()
    for fmt in ("%Y-%m", "%Y/%m", "%m/%Y", "%m-%Y", "%m.%Y", "%B %Y", "%b %Y", "%Y"):
        try:
            dt.datetime.strptime(text, fmt)
            return True
        except ValueError:
            continue
    return False


def collect_privacy_records(input_dir: Path, max_bytes: int = 50 * 1024 * 1024) -> list[PrivacyRecord]:
    """Read QI-bearing values and output paths without writing raw values anywhere."""
    records: list[PrivacyRecord] = []
    for current, dirs, names in os.walk(input_dir, followlinks=False):
        base = Path(current)
        dirs[:] = sorted(d for d in dirs if not (base / d).is_symlink())
        for name in sorted(names):
            path = base / name
            if path.is_symlink() or path.suffix.lower() not in SUPPORTED:
                continue
            try:
                if path.stat().st_size > max_bytes:
                    continue
                rel = path.relative_to(input_dir).as_posix()
                text = decode_input(path.read_bytes())
                suffix = path.suffix.lower()
                if suffix in {".csv", ".tsv"}:
                    rows = list(csv.reader(text.splitlines(), delimiter="\t" if suffix == ".tsv" else ",", strict=True))
                    if not rows:
                        continue
                    for row_index, row in enumerate(rows[1:]):
                        item = PrivacyRecord(rel, f"row:{row_index}", suffix[1:])
                        for column, value in enumerate(row):
                            if column < len(rows[0]):
                                kind = _key_kind(rows[0][column])
                                if kind:
                                    item.add(kind, value, rows[0][column], (column,))
                        records.append(item)
                elif suffix == ".json":
                    data = json.loads(text)
                    for loc, root, node in _record_roots(data, rel):
                        item = PrivacyRecord(rel, loc, "json")
                        _walk_json(item, node, root)
                        records.append(item)
                else:
                    item = PrivacyRecord(rel, "doc", "text")
                    _text_fields(item, text)
                    records.append(item)
            except (OSError, UnicodeError, ValueError, csv.Error, RecursionError):
                continue
    return sorted(records, key=lambda item: (item.file, item.loc))
