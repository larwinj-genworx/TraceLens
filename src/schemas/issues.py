from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


class ConfidenceBand(str, Enum):
    DETERMINISTIC = "deterministic"
    CORROBORATED = "corroborated"
    HEURISTIC = "heuristic"


class Issue(BaseModel):
    type: str
    severity: Severity
    service: str
    endpoint: str | None = None
    file: str | None = None
    line: int | None = None
    description: str
    evidence: dict[str, Any] = Field(default_factory=dict)
    impact: str
    fix: str
    confidence: float = Field(default=0.8, ge=0.0, le=1.0)
    confidence_band: ConfidenceBand = Field(default=ConfidenceBand.HEURISTIC)
    advisory: bool = False
    provenance: list[str] = Field(default_factory=list)
    source: str | None = Field(default=None, description="Agent that produced this issue")
