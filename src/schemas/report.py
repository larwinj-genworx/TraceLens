from __future__ import annotations

from pydantic import BaseModel, Field

from src.schemas.issues import Issue


class ReportSummary(BaseModel):
    score: int = Field(ge=0, le=100)
    critical: int = 0
    high: int = 0
    medium: int = 0


class AnalysisReport(BaseModel):
    summary: ReportSummary
    assumptions: list[str] = Field(default_factory=list)
    issues: list[Issue] = Field(default_factory=list)
