"""Risk-aware, deterministic quasi-identifier transformations."""

from src.privacy.date_shifter import DateShifter
from src.privacy.generalization import age_band, generalize_stay, parse_age
from src.privacy.extractor import PrivacyAction, PrivacyRecord, collect_privacy_records
from src.privacy.risk import equivalence_summary
from src.privacy.transform import build_privacy_actions

__all__ = [
    "DateShifter", "PrivacyAction", "PrivacyRecord", "age_band", "build_privacy_actions",
    "collect_privacy_records", "equivalence_summary", "generalize_stay", "parse_age",
]
