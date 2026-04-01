from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"


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
