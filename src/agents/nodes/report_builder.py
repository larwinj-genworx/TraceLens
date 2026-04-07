from __future__ import annotations

from typing import Any

from src.agents.state import AgentState
from src.config.settings import settings
from src.observability.logging.setup import get_logger
from src.schemas.internal import AnalysisContext
from src.schemas.issues import Issue, Severity
from src.schemas.report import AnalysisReport, ReportSummary

logger = get_logger(__name__)


def build_report(state: AgentState) -> dict[str, Any]:
    """Deterministic node: take reviewed issues and assemble the final
    AnalysisReport with scoring, sorting, and metadata."""
    reviewed: list[Issue] = state.get("reviewed_issues", [])
    ctx: AnalysisContext = state["analysis_context"]
    logger.info("report_builder started issues=%d", len(reviewed))

    capped = reviewed[: settings.agent_max_issues_per_scan]
    if len(reviewed) > settings.agent_max_issues_per_scan:
        logger.warning(
            "report_builder capped issues from %d to %d",
            len(reviewed),
            settings.agent_max_issues_per_scan,
        )

    severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}
    capped.sort(
        key=lambda i: (severity_order.get(i.severity, 3), -i.confidence, i.type, i.service),
    )

    summary = _build_summary(capped)

    assumptions: list[str] = list(ctx.env_result.assumptions)
    assumptions.append("Issues were identified by multi-agent LLM analysis with cross-review verification.")

    report = AnalysisReport(
        summary=summary,
        assumptions=sorted(set(assumptions)),
        issues=capped,
        flow_summary=ctx.flow_summary,
        flow_coverage=ctx.flow_coverage,
        observations=ctx.observations,
    )

    logger.info(
        "report_builder done score=%d critical=%d high=%d medium=%d",
        summary.score,
        summary.critical,
        summary.high,
        summary.medium,
    )
    return {"report": report}


def _build_summary(issues: list[Issue]) -> ReportSummary:
    critical = sum(1 for i in issues if i.severity == Severity.CRITICAL)
    high = sum(1 for i in issues if i.severity == Severity.HIGH)
    medium = sum(1 for i in issues if i.severity == Severity.MEDIUM)
    score = max(0, 100 - (critical * 18) - (high * 8) - (medium * 3))
    return ReportSummary(score=score, critical=critical, high=high, medium=medium)
