"""PII-bearing linkage models. Do not serialize or log their contents."""

from __future__ import annotations

from dataclasses import dataclass, field


@dataclass(frozen=True, repr=False)
class IdentitySignal:
    category: str
    value: str
    namespace: str = ""


@dataclass(frozen=True)
class Carrier:
    """Original patient-scoped field location used for safe output replacement."""

    category: str
    path: tuple[str | int, ...] = ()


@dataclass(repr=False)
class RecordIdentity:
    file: str
    loc: str
    file_format: str
    signals: list[IdentitySignal] = field(default_factory=list)
    carrier: Carrier | None = None
    patient_name_spans: list[tuple[int, int]] = field(default_factory=list)

    def add(self, category: str, value: str, namespace: str = "") -> None:
        if value:
            signal = IdentitySignal(category, value, namespace)
            if signal not in self.signals:
                self.signals.append(signal)


@dataclass(frozen=True, repr=False)
class LinkDecision:
    left: tuple[str, str]
    right: tuple[str, str]
    state: str
    confidence: float
    evidence: tuple[str, ...]


@dataclass
class LinkResult:
    records: list[RecordIdentity]
    pseudonyms: dict[tuple[str, str], str]
    decisions: list[LinkDecision]
    linked_record_count: int
    unresolved_record_count: int
