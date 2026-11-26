"""Patient-specific deterministic date shifts using a secret HMAC key."""

from __future__ import annotations

import datetime as dt
import hashlib
import hmac
import re
from dataclasses import dataclass


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
    ("%d-%m-%Y", re.compile(r"(?<!\d)(\d{1,2}-\d{1,2}-\d{4})(?!\d)")),
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
        if not isinstance(secret, str) or not secret.strip() or len(secret.encode("utf-8")) < 16:
            raise ValueError("RAKSHA_SECRET is invalid")
        if not isinstance(maximum_days, int) or maximum_days < 1 or maximum_days > 3650:
            raise ValueError("date_shift_max_days is invalid")
        self._key = secret.encode("utf-8")
        self.maximum_days = maximum_days

    def offset_days(self, patient_pseudonym: str) -> int:
        if not patient_pseudonym or not patient_pseudonym.startswith("PSN-"):
            raise ValueError("patient_identity_unresolved")
        digest = hmac.new(self._key, self.DOMAIN + patient_pseudonym.encode("utf-8"), hashlib.sha256).digest()
        width = self.maximum_days * 2
        offset = int.from_bytes(digest[:8], "big") % width - self.maximum_days
        return offset if offset else 1

    def shift(self, value: dt.date | dt.datetime, patient_pseudonym: str) -> dt.date | dt.datetime:
        return value + dt.timedelta(days=self.offset_days(patient_pseudonym))
