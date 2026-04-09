from __future__ import annotations

from pydantic import BaseModel, Field

from src.schemas.issues import Issue
from src.schemas.internal import FlowCoverageItem, FlowSummaryItem, Observation, TypeDiagnostic


class ReportSummary(BaseModel):
    score: int = Field(ge=0, le=100)
    critical: int = 0
    high: int = 0
    medium: int = 0


class StandardsComplianceSection(BaseModel):
    """Per-category compliance result from standards checking."""

    category: str
    declared_style: str
    status: str = "not_applicable"
    confidence: float = 0.0
    evidence_count: int = 0
    violations: int = 0
    compliant: int = 0
    summary: str = ""
    findings: list[Issue] = Field(default_factory=list)
    evidence_summary: list[dict] = Field(default_factory=list)


class CoverageMatrixRow(BaseModel):
    stack: str = "fastapi"
    service: str
    category: str
    endpoint: str
    checked: bool = False
    status: str = "unchecked"
    file: str | None = None
    line: int | None = None


class CoverageMatrix(BaseModel):
    total_checks: int = 0
    checked: int = 0
    unchecked: int = 0
    coverage_pct: float = 100.0
    rows: list[CoverageMatrixRow] = Field(default_factory=list)
    unchecked_details: list[CoverageMatrixRow] = Field(default_factory=list)


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
    standard_used: str | None = Field(default=None, description="TraceLens standard ID used for this analysis")
    standards_compliance: list[StandardsComplianceSection] = Field(
        default_factory=list,
        description="Per-category standards compliance results",
    )
    mandatory_compliance: list[StandardsComplianceSection] = Field(
        default_factory=list,
        description="Mandatory built-in rule compliance sections.",
    )
    folder_structure_compliance: StandardsComplianceSection | None = Field(
        default=None,
        description="Folder-structure compliance details from template checks.",
    )
    coverage_matrix: CoverageMatrix = Field(
        default_factory=CoverageMatrix,
        description="Endpoint/category coverage matrix with checked rows.",
    )
