"""Patient-specific deterministic date shifts using a secret HMAC key."""

from __future__ import annotations

import calendar
import datetime as dt
import hmac
import re
from dataclasses import dataclass

from src.security.secret_manager import derive_key


@dataclass(frozen=True, repr=False)
class ParsedDate:
    value: dt.datetime
    format_name: str
    has_time: bool = False
    suffix: str = ""


_DATE_FORMATS = (
    ("%Y-%m-%d", re.compile(r"(?<!\d)(\d{4}-\d{1,2}-\d{1,2})(?!\d)")),
    ("%Y/%m/%d", re.compile(r"(?<!\d)(\d{4}/\d{1,2}/\d{1,2})(?!\d)")),
    ("%d/%m/%Y", re.compile(r"(?<!\d)(\d{1,2}/\d{1,2}/\d{4})(?!\d)")),
    # Use US month/day ordering only after the Indian day/month parser fails.
    ("%m/%d/%Y", re.compile(r"(?<!\d)(\d{1,2}/\d{1,2}/\d{4})(?!\d)")),
    ("%d-%m-%Y", re.compile(r"(?<!\d)(\d{1,2}-\d{1,2}-\d{4})(?!\d)")),
    ("%m-%d-%Y", re.compile(r"(?<!\d)(\d{1,2}-\d{1,2}-\d{4})(?!\d)")),
    ("%d.%m.%Y", re.compile(r"(?<!\d)(\d{1,2}\.\d{1,2}\.\d{4})(?!\d)")),
    ("%d/%m/%y", re.compile(r"(?<!\d)(\d{1,2}/\d{1,2}/\d{2})(?!\d)")),
    ("%d-%m-%y", re.compile(r"(?<!\d)(\d{1,2}-\d{1,2}-\d{2})(?!\d)")),
)
_MONTH_WORD = re.compile(r"(?i)(?<!\w)(\d{1,2}\s+[A-Za-z]{3,9}\s+\d{4})(?!\w)")
_ISO_TIMESTAMP = re.compile(
    r"(?<!\d)(\d{4}-\d{2}-\d{2})(T|\s)(\d{2}:\d{2}:\d{2}(?:\.\d+)?)(Z|[+-]\d{2}:?\d{2})?"
)


class DateShifter:
    """Derive a bounded offset for one resolved patient and shift calendar dates."""

    DOMAIN = b"secret-wards/date-shift/v1\0"

    def __init__(self, secret: str, maximum_days: int = 365) -> None:
        if not isinstance(maximum_days, int) or maximum_days < 1 or maximum_days > 3650:
            raise ValueError("date_shift_max_days is invalid")
        self._key = derive_key(secret, "date-shift/v2")
        self.maximum_days = maximum_days

    def offset_days(self, patient_pseudonym: str) -> int:
        if not patient_pseudonym or not patient_pseudonym.startswith("PSN-"):
            raise ValueError("patient_identity_unresolved")
        digest = hmac.new(self._key, self.DOMAIN + patient_pseudonym.encode("utf-8"), "sha256").digest()
        width = self.maximum_days * 2
        offset = int.from_bytes(digest[:8], "big") % width - self.maximum_days
        return offset if offset else 1

    def shift(self, value: dt.date | dt.datetime, patient_pseudonym: str) -> dt.date | dt.datetime:
        return value + dt.timedelta(days=self.offset_days(patient_pseudonym))


def parse_date(value: str) -> ParsedDate | None:
    """Parse a full calendar date, preferring Indian day/month ordering."""
    text = value.strip()
    timestamp = _ISO_TIMESTAMP.fullmatch(text)
    if timestamp:
        date_part, separator, time_part, zone = timestamp.groups()
        try:
            date = dt.date.fromisoformat(date_part)
            time_value = dt.time.fromisoformat(time_part)
            parsed = dt.datetime.combine(date, time_value)
            suffix = ("Z" if zone == "Z" else "") if zone else ""
            if zone and zone != "Z":
                normalized_zone = zone if ":" in zone else zone[:3] + ":" + zone[3:]
                parsed = dt.datetime.fromisoformat(date_part + "T" + time_part + normalized_zone)
                suffix = normalized_zone
            return ParsedDate(parsed, "iso-timestamp", True, suffix)
        except ValueError:
            return None
    for fmt, pattern in _DATE_FORMATS:
        match = pattern.fullmatch(text)
        if not match:
            continue
        try:
            return ParsedDate(dt.datetime.strptime(match.group(1), fmt), fmt)
        except ValueError:
            continue
    match = _MONTH_WORD.fullmatch(text)
    if match:
        for fmt in ("%d %B %Y", "%d %b %Y"):
            try:
                return ParsedDate(dt.datetime.strptime(match.group(1), fmt), fmt)
            except ValueError:
                pass
    return None


def format_date(value: dt.date | dt.datetime, parsed: ParsedDate, original: str) -> str:
    if parsed.has_time:
        date_part, separator, rest = original.partition("T")
        if not separator:
            date_part, separator, rest = original.partition(" ")
        shifted = value.strftime("%Y-%m-%d")
        return shifted + separator + rest if separator else shifted
    if parsed.format_name in {"%m/%d/%Y", "%m-%d-%Y"}:
        # The shifted month/day form could be re-read as Indian day/month.
        return value.strftime("%Y-%m-%d")
    if parsed.format_name in {"%d/%m/%Y", "%d/%m/%y", "%d-%m-%Y", "%d-%m-%y", "%d.%m.%Y"}:
        fmt = parsed.format_name
    elif parsed.format_name == "%Y/%m/%d":
        fmt = "%Y/%m/%d"
    elif parsed.format_name in {"%d %B %Y", "%d %b %Y"}:
        fmt = parsed.format_name
    else:
        fmt = "%Y-%m-%d"
    return value.strftime(fmt)


def month_precision(value: str) -> str:
    """Return a month-level value for an unresolved record without keeping its day."""
    parsed = parse_date(value)
    if parsed is None:
        # Malformed ISO calendar dates cannot be shifted as real dates. Keep
        # only their valid year/month so impossible day tokens do not pass
        # through unchanged as quasi-identifiers.
        coarse = invalid_iso_month(value)
        if coarse:
            return coarse
        return value
    if parsed.format_name == "%d/%m/%Y" or parsed.format_name == "%d/%m/%y":
        return parsed.value.strftime("%m/%Y")
    if parsed.format_name == "%m/%d/%Y":
        return parsed.value.strftime("%m/%Y")
    if parsed.format_name in {"%d-%m-%Y", "%d-%m-%y"}:
        return parsed.value.strftime("%m-%Y")
    if parsed.format_name == "%m-%d-%Y":
        return parsed.value.strftime("%m-%Y")
    if parsed.format_name == "%d.%m.%Y":
        return parsed.value.strftime("%m.%Y")
    if parsed.format_name in {"%d %B %Y", "%d %b %Y"}:
        return parsed.value.strftime("%B %Y")
    if parsed.has_time:
        return parsed.value.strftime("%Y-%m")
    return parsed.value.strftime("%Y-%m")


def invalid_iso_month(value: str) -> str | None:
    """Return a month for an ISO-like date with a valid month but impossible day."""
    match = re.fullmatch(r"(\d{4})-(\d{1,2})-(\d{1,2})", value.strip())
    if not match:
        return None
    year, month, day = map(int, match.groups())
    if not 1 <= month <= 12:
        return None
    if 1 <= day <= calendar.monthrange(year, month)[1]:
        return None
    return f"{year:04d}-{month:02d}"
