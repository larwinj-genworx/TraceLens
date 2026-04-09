"""LangGraph workflow for multi-agent evidence-based analysis.

The compiled graph is:

  prepare_evidence
        |
   +----+----+
   v    v    v
  sec  int  qual   (fan-out -- executed sequentially to respect Groq RPM)
   +----+----+
        v
   consolidate
        v
   deterministic_filter   (hard guardrail -- drops issues contradicting evidence)
        v
   cross_review
        v
   build_report
"""
from __future__ import annotations

import json
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

from langgraph.graph import END, StateGraph

from src.agents.nodes.consolidator import consolidate_issues
from src.agents.nodes.cross_reviewer import review_issues
from src.agents.nodes.deterministic_filter import filter_issues
from src.agents.nodes.evidence_preparator import prepare_evidence
from src.agents.nodes.integration_analyst import analyze_integration
from src.agents.nodes.quality_analyst import analyze_quality
from src.agents.nodes.report_builder import build_report
from src.agents.nodes.security_analyst import analyze_security
from src.agents.state import AgentState
from src.config.settings import settings
from src.observability.logging.setup import get_logger
from src.schemas.internal import AnalysisContext
from src.schemas.issues import Issue
from src.schemas.report import AnalysisReport

logger = get_logger(__name__)

ProgressCallback = Callable[[dict[str, Any]], Awaitable[None] | None]


def _build_graph() -> StateGraph:
    """Construct and compile the LangGraph StateGraph."""
    graph = StateGraph(AgentState)

    graph.add_node("prepare_evidence", prepare_evidence)
    graph.add_node("analyze_security", analyze_security)
    graph.add_node("analyze_integration", analyze_integration)
    graph.add_node("analyze_quality", analyze_quality)
    graph.add_node("consolidate", consolidate_issues)
    graph.add_node("deterministic_filter", filter_issues)
    graph.add_node("cross_review", review_issues)
    graph.add_node("build_report", build_report)

    graph.set_entry_point("prepare_evidence")

    graph.add_edge("prepare_evidence", "analyze_security")
    graph.add_edge("analyze_security", "analyze_integration")
    graph.add_edge("analyze_integration", "analyze_quality")
    graph.add_edge("analyze_quality", "consolidate")
    graph.add_edge("consolidate", "deterministic_filter")
    graph.add_edge("deterministic_filter", "cross_review")
    graph.add_edge("cross_review", "build_report")
    graph.add_edge("build_report", END)

    return graph


_compiled = _build_graph().compile()

_TRACE_NODE_FILES: dict[str, tuple[str, str]] = {
    "prepare_evidence": ("01_evidence_package.json", "evidence_package"),
    "analyze_security": ("02_security_issues.json", "security_issues"),
    "analyze_integration": ("03_integration_issues.json", "integration_issues"),
    "analyze_quality": ("04_quality_issues.json", "quality_issues"),
    "consolidate": ("05_consolidated_issues.json", "consolidated_issues"),
    "deterministic_filter": ("05b_filtered_issues.json", "consolidated_issues"),
    "cross_review": ("06_reviewed_issues.json", "reviewed_issues"),
    "build_report": ("07_final_report.json", "report"),
}


def _write_trace(job_id: str, node_name: str, data: Any) -> None:
    """Write a trace file for the given node if tracing is enabled."""
    if not settings.evidence_trace_enabled:
        return

    mapping = _TRACE_NODE_FILES.get(node_name)
    if not mapping:
        return

    filename, _ = mapping
    trace_dir = settings.evidence_trace_dir / job_id
    trace_dir.mkdir(parents=True, exist_ok=True)
    filepath = trace_dir / filename

    def _serialize(obj: Any) -> Any:
        if hasattr(obj, "model_dump"):
            return obj.model_dump(mode="json")
        if hasattr(obj, "value"):
            return obj.value
        return str(obj)

    trace_payload = {
        "_meta": {
            "job_id": job_id,
            "node": node_name,
            "timestamp": datetime.now(timezone.utc).isoformat(),
        },
        "data": data,
    }

    try:
        filepath.write_text(
            json.dumps(trace_payload, indent=2, default=_serialize, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("trace written: %s", filepath)
    except Exception:
        logger.exception("trace write failed: %s", filepath)


async def run_analysis_graph(
    context: AnalysisContext,
    progress_cb: ProgressCallback | None = None,
    job_id: str | None = None,
    standards_context: dict[str, Any] | None = None,
) -> tuple[list[Issue], list[str]]:
    """Execute the multi-agent analysis graph and return (issues, observations).

    This is the single entry-point that the ValidationOrchestrator calls.
    """
    if job_id is None:
        job_id = uuid.uuid4().hex[:12]

    logger.info("langgraph_workflow started job_id=%s", job_id)

    initial_state: AgentState = {
        "job_id": job_id,
        "analysis_context": context,
        "evidence_package": {},
        "standards_context": standards_context or {},
        "security_issues": [],
        "integration_issues": [],
        "quality_issues": [],
        "consolidated_issues": [],
        "reviewed_issues": [],
        "report": None,
        "progress_events": [],
        "errors": [],
    }

    _stages = [
        ("prepare_evidence", "Preparing evidence package for agents"),
        ("analyze_security", "Security analyst agent scanning"),
        ("analyze_integration", "Integration analyst agent scanning"),
        ("analyze_quality", "Quality analyst agent scanning"),
        ("consolidate", "Consolidating and deduplicating issues"),
        ("deterministic_filter", "Applying deterministic evidence guardrails"),
        ("cross_review", "Cross-review agent verifying accuracy"),
        ("build_report", "Building final report"),
    ]
    stage_idx = 0
    final_state = initial_state

    async for event in _compiled.astream(initial_state, stream_mode="updates"):
        for node_name, node_output in event.items():
            if isinstance(node_output, dict):
                final_state = {**final_state, **node_output}

            mapping = _TRACE_NODE_FILES.get(node_name)
            if mapping and isinstance(node_output, dict):
                _, state_key = mapping
                trace_data = node_output.get(state_key, node_output)
                _write_trace(job_id, node_name, trace_data)

            if stage_idx < len(_stages):
                stage_id, stage_msg = _stages[stage_idx]
                await _emit(progress_cb, stage_id, stage_msg)
                stage_idx += 1

    report: AnalysisReport | None = final_state.get("report")
    if report is None:
        logger.error("langgraph_workflow no report produced")
        return [], ["Multi-agent analysis produced no report"]

    observations: list[str] = []
    reviewed = final_state.get("reviewed_issues", [])
    consolidated = final_state.get("consolidated_issues", [])
    if len(consolidated) > len(reviewed):
        observations.append(
            f"Cross-reviewer removed {len(consolidated) - len(reviewed)} false-positive candidates."
        )

    logger.info(
        "langgraph_workflow done issues=%d score=%d",
        len(report.issues),
        report.summary.score,
    )
    return report.issues, observations


async def _emit(
    callback: ProgressCallback | None,
    stage: str,
    message: str,
) -> None:
    if callback is None:
        return
    import inspect

    event = {"stage": stage, "message": message}
    result = callback(event)
    if inspect.isawaitable(result):
        await result
