"""Extract quasi-identifier fields and safe transformation paths in memory."""

from __future__ import annotations

import csv
import json
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.linkage.extractor import decode_input
from src.privacy.date_shifter import parse_date

SUPPORTED = {".csv", ".tsv", ".json", ".txt"}
_DATE_KEY = re.compile(r"date|datetime|birth|dob|admission|discharge|visit|encounter|recorded|effective|performed|onset|lastupdated", re.I)
_AGE_KEY = re.compile(r"^(?:age|patientage|age_sex|ageyears|umar|वय|आयु|उम्र)$", re.I)
_DATE_VALUE = re.compile(
    r"(?<!\d)(?:\d{4}-\d{1,2}-\d{1,2}(?:[T ][0-9:.+-]+Z?)?|\d{1,2}[./-]\d{1,2}[./-]\d{2,4}|\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})(?!\d)"
)


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
    if normalized in {"createdat", "updatedat", "createdon", "updatedon", "exportedat", "timestamp", "timestamputc"}:
        return "event_date"
    if _DATE_KEY.search(normalized) or (normalized in {"start", "end"} and "encounterperiod" in parent_n):
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
