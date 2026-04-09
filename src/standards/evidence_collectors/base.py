"""Base evidence collector and result types."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Literal


@dataclass
class Evidence:
    """A single piece of evidence collected for standards compliance."""

    category: str
    style: str
    status: Literal["compliant", "violation", "partial", "not_found"]
    file: str = ""
    line: int | None = None
    endpoint: str | None = None
    service: str | None = None
    details: dict[str, Any] = field(default_factory=dict)
    confidence: float = 0.8
    message: str = ""


@dataclass
class CategoryEvidenceResult:
    """Aggregated evidence for a single category."""

    category: str
    declared_style: str
    overall_status: Literal["compliant", "non_compliant", "partial", "not_applicable"]
    evidence_items: list[Evidence] = field(default_factory=list)
    confidence: float = 0.0
    summary: str = ""

    def add(self, evidence: Evidence) -> None:
        self.evidence_items.append(evidence)

    def compute_status(self) -> None:
        if not self.evidence_items:
            self.overall_status = "not_applicable"
            self.confidence = 0.0
            return

        violations = [e for e in self.evidence_items if e.status == "violation"]
        compliant = [e for e in self.evidence_items if e.status == "compliant"]
        partial = [e for e in self.evidence_items if e.status == "partial"]

        if not violations and not partial:
            self.overall_status = "compliant"
        elif violations and not compliant:
            self.overall_status = "non_compliant"
        else:
            self.overall_status = "partial"

        all_conf = [e.confidence for e in self.evidence_items]
        self.confidence = sum(all_conf) / len(all_conf) if all_conf else 0.0
