from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from src.agents.llm_client import RateLimitedGroqClient
from src.agents.nodes.parsing import parse_issues_from_response
from src.agents.prompts.security import SECURITY_ANALYST_SYSTEM
from src.agents.state import AgentState
from src.config.settings import settings
from src.observability.logging.setup import get_logger

logger = get_logger(__name__)

SOURCE = "security_analyst"
_MAX_EVIDENCE_CHARS = 12_000
_MAX_SNIPPETS = 10


async def analyze_security(state: AgentState) -> dict[str, Any]:
    """LangGraph node: run the security analyst agent."""
    evidence: dict[str, Any] = state["evidence_package"]["security"]
    logger.info("security_analyst started endpoints=%d", len(evidence.get("endpoints", [])))

    trimmed = _trim_evidence(evidence)
    evidence_text = json.dumps(trimmed, indent=None, default=str, ensure_ascii=False)
    if len(evidence_text) > _MAX_EVIDENCE_CHARS:
        evidence_text = evidence_text[:_MAX_EVIDENCE_CHARS] + " ..."
    logger.info("security_analyst evidence_chars=%d", len(evidence_text))

    standards_ctx = state.get("standards_context", {})
    standards_addendum = _build_standards_addendum(standards_ctx)

    client = RateLimitedGroqClient(model=settings.groq_scanner_model)
    system_prompt = SECURITY_ANALYST_SYSTEM
    if standards_addendum:
        system_prompt += "\n\n" + standards_addendum

    messages = [
        SystemMessage(content=system_prompt),
        HumanMessage(content=f"Analyse the following evidence and report security issues.\n\nEVIDENCE:\n{evidence_text}"),
    ]

    try:
        raw_response = await client.invoke(messages)
        issues = parse_issues_from_response(raw_response, SOURCE)
    except Exception:
        logger.exception("security_analyst_failed")
        issues = []

    logger.info("security_analyst done issues=%d", len(issues))
    return {"security_issues": issues}


def _build_standards_addendum(ctx: dict[str, Any]) -> str:
    """Build a prompt addendum from standards context."""
    if not ctx:
        return ""
    parts = [
        "--- USER-DECLARED STANDARDS CONTEXT ---",
        f"The user has declared how their application implements each concern.",
        f"Standard: {ctx.get('standard_name', 'unnamed')} (id: {ctx.get('standard_id', '')})",
    ]
    fastapi = ctx.get("fastapi", {})
    if fastapi:
        parts.append("\nBackend (FastAPI) declared styles:")
        for cat_id, cat_data in fastapi.items():
            if cat_id == "folder_structure":
                continue
            if isinstance(cat_data, dict):
                parts.append(f"  - {cat_id}: {cat_data.get('style', '?')}")
        auth_style = fastapi.get("auth_style", {})
        if isinstance(auth_style, dict) and auth_style.get("style") == "global_middleware":
            parts.append(
                "\nCRITICAL: The user declared global_middleware for authentication. "
                "This means ALL non-public routes are protected by middleware. "
                "Do NOT flag missing_auth on any route unless it is explicitly excluded from middleware scope."
            )
        auth_style_val = auth_style.get("style", "") if isinstance(auth_style, dict) else ""
        if auth_style_val == "decorator":
            parts.append(
                "\nThe user declared decorator-based auth. Only flag missing_auth if "
                "the route has no auth decorator AND no other auth mechanism."
            )
    parts.append("--- END STANDARDS CONTEXT ---")
    return "\n".join(parts)


def _trim_evidence(ev: dict[str, Any]) -> dict[str, Any]:
    """Cap list sizes and include a limited set of code snippets."""
    out: dict[str, Any] = {}
    for key, val in ev.items():
        if key == "code_snippets":
            if isinstance(val, dict):
                trimmed_snippets = dict(list(val.items())[:_MAX_SNIPPETS])
                out[key] = trimmed_snippets
            continue
        if isinstance(val, list):
            out[key] = val[:40]
        else:
            out[key] = val
    return out
