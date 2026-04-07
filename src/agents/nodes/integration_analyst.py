from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from src.agents.llm_client import RateLimitedGroqClient
from src.agents.nodes.parsing import parse_issues_from_response
from src.agents.prompts.integration import INTEGRATION_ANALYST_SYSTEM
from src.agents.state import AgentState
from src.config.settings import settings
from src.observability.logging.setup import get_logger

logger = get_logger(__name__)

SOURCE = "integration_analyst"
_MAX_EVIDENCE_CHARS = 12_000


async def analyze_integration(state: AgentState) -> dict[str, Any]:
    """LangGraph node: run the integration/contract analyst agent."""
    evidence: dict[str, Any] = state["evidence_package"]["integration"]
    logger.info(
        "integration_analyst started matches=%d contracts=%d",
        len(evidence.get("graph_matches", [])),
        len(evidence.get("contract_violations", [])),
    )

    trimmed = _trim_evidence(evidence)
    evidence_text = json.dumps(trimmed, indent=None, default=str, ensure_ascii=False)
    if len(evidence_text) > _MAX_EVIDENCE_CHARS:
        evidence_text = evidence_text[:_MAX_EVIDENCE_CHARS] + " ..."
    logger.info("integration_analyst evidence_chars=%d", len(evidence_text))

    client = RateLimitedGroqClient(model=settings.groq_scanner_model)
    messages = [
        SystemMessage(content=INTEGRATION_ANALYST_SYSTEM),
        HumanMessage(content=f"Analyse the following evidence and report integration/contract issues.\n\nEVIDENCE:\n{evidence_text}"),
    ]

    try:
        raw_response = await client.invoke(messages)
        issues = parse_issues_from_response(raw_response, SOURCE)
    except Exception:
        logger.exception("integration_analyst_failed")
        issues = []

    logger.info("integration_analyst done issues=%d", len(issues))
    return {"integration_issues": issues}


def _trim_evidence(ev: dict[str, Any]) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for key, val in ev.items():
        if key == "code_snippets":
            continue
        if isinstance(val, list):
            out[key] = val[:40]
        else:
            out[key] = val
    return out
