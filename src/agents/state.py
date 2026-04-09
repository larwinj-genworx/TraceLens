from __future__ import annotations

from typing import Any, TypedDict

from src.schemas.internal import AnalysisContext
from src.schemas.issues import Issue
from src.schemas.report import AnalysisReport


class AgentState(TypedDict, total=False):
    job_id: str
    analysis_context: AnalysisContext
    evidence_package: dict[str, Any]
    standards_context: dict[str, Any]
    security_issues: list[Issue]
    integration_issues: list[Issue]
    quality_issues: list[Issue]
    consolidated_issues: list[Issue]
    reviewed_issues: list[Issue]
    report: AnalysisReport | None
    progress_events: list[dict[str, Any]]
    errors: list[str]
