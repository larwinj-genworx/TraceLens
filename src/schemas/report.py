from __future__ import annotations

from pydantic import BaseModel, Field

from src.schemas.issues import Issue
from src.schemas.internal import FlowCoverageItem, FlowSummaryItem, Observation, TypeDiagnostic


class ReportSummary(BaseModel):
    score: int = Field(ge=0, le=100)
    critical: int = 0
    high: int = 0
    medium: int = 0


class AnalysisReport(BaseModel):
    summary: ReportSummary
    assumptions: list[str] = Field(default_factory=list)
    issues: list[Issue] = Field(default_factory=list)
    advisories: list[Issue] = Field(default_factory=list)
    type_diagnostics: list[TypeDiagnostic] = Field(default_factory=list)
    provenance_summary: dict[str, int] = Field(default_factory=dict)
    flow_summary: list[FlowSummaryItem] = Field(default_factory=list)
    flow_coverage: list[FlowCoverageItem] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
