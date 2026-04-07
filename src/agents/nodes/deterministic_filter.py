"""Deterministic post-consolidation filter.

Runs after the LLM analyst agents and consolidator but before the
cross-reviewer.  Removes issues that directly contradict pre-computed
deterministic evidence fields -- regardless of what the LLM generated.

This is the hard guardrail that prevents LLM hallucinations from reaching
the final report when clear static-analysis signals exist.
"""
from __future__ import annotations

import re
from typing import Any

from src.agents.state import AgentState
from src.observability.logging.setup import get_logger
from src.schemas.issues import Issue

logger = get_logger(__name__)

_TOKEN_FIELDS: frozenset[str] = frozenset({
    "access_token", "token", "refresh_token", "id_token",
    "bearer_token", "jwt", "auth_token",
})

_METHOD_RE = re.compile(
    r"^(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|WS)\s+",
    re.IGNORECASE,
)


def _endpoint_path(endpoint: str | None) -> str:
    if not endpoint:
        return ""
    return _METHOD_RE.sub("", endpoint).strip()


def _build_endpoint_index(
    endpoints: list[dict[str, Any]],
) -> dict[str, dict[str, Any]]:
    """Index endpoint evidence by ``METHOD /canonical_path``."""
    idx: dict[str, dict[str, Any]] = {}
    for ep in endpoints:
        method = (ep.get("method") or "").upper()
        path = ep.get("canonical_path") or ep.get("path") or ""
        key = f"{method} {path}"
        idx[key] = ep
        raw_key = f"{method} {ep.get('path', '')}"
        if raw_key != key:
            idx[raw_key] = ep
    return idx


def _build_contract_violation_keys(
    contract_violations: list[dict[str, Any]],
) -> set[tuple[str, str | None]]:
    """Set of ``(violation_type, endpoint)`` from deterministic contract validator."""
    keys: set[tuple[str, str | None]] = set()
    for cv in contract_violations:
        keys.add((cv.get("type", ""), cv.get("endpoint")))
    return keys


def filter_issues(state: AgentState) -> dict[str, Any]:
    """LangGraph node: deterministically remove issues that contradict
    pre-computed evidence fields."""
    consolidated: list[Issue] = state.get("consolidated_issues", [])
    full_evidence: dict[str, Any] = state["evidence_package"].get("full", {})
    logger.info("deterministic_filter started candidates=%d", len(consolidated))

    if not consolidated:
        return {"consolidated_issues": []}

    ep_index = _build_endpoint_index(full_evidence.get("endpoints", []))
    cv_keys = _build_contract_violation_keys(
        full_evidence.get("contract_violations", [])
    )

    kept: list[Issue] = []
    removed_reasons: list[str] = []

    for issue in consolidated:
        reason = _should_drop(issue, ep_index, cv_keys)
        if reason:
            removed_reasons.append(
                f"{issue.type} @ {issue.endpoint}: {reason}"
            )
            logger.info(
                "deterministic_filter dropped type=%s endpoint=%s reason=%s",
                issue.type, issue.endpoint, reason,
            )
        else:
            kept.append(issue)

    removed = len(consolidated) - len(kept)
    if removed:
        logger.info(
            "deterministic_filter removed=%d kept=%d reasons=%s",
            removed, len(kept), removed_reasons,
        )
    else:
        logger.info("deterministic_filter kept all %d issues", len(kept))

    return {"consolidated_issues": kept}


def _should_drop(
    issue: Issue,
    ep_index: dict[str, dict[str, Any]],
    cv_keys: set[tuple[str, str | None]],
) -> str | None:
    """Return a drop-reason string if the issue should be removed, else None."""

    ep_evidence = _find_endpoint(issue, ep_index)

    if issue.type == "missing_ownership_check" and ep_evidence:
        om = ep_evidence.get("ownership_mode", "")
        if om in ("covered", "ambiguous", "not_applicable"):
            return f"ownership_mode={om}"

    if issue.type == "missing_auth" and ep_evidence:
        if ep_evidence.get("auth_covered") is True:
            return "auth_covered=true"
        am = ep_evidence.get("auth_mode", "")
        if am and am != "missing":
            return f"auth_mode={am}"

    if issue.type == "missing_fields":
        if ("missing_fields", issue.endpoint) not in cv_keys:
            return "no contract_violations entry for missing_fields"

    if issue.type == "data_leakage" and ep_evidence:
        ri = ep_evidence.get("route_intent", "")
        if ri == "auth_entry":
            evidence_fields = issue.evidence.get("sensitive_fields", [])
            flagged_desc = issue.description.lower()
            if _only_token_fields(evidence_fields, flagged_desc):
                return "auth_entry endpoint returning expected token fields"

    return None


def _find_endpoint(
    issue: Issue,
    ep_index: dict[str, dict[str, Any]],
) -> dict[str, Any] | None:
    """Look up endpoint evidence for an issue."""
    if issue.endpoint:
        ep = ep_index.get(issue.endpoint)
        if ep:
            return ep
        path = _endpoint_path(issue.endpoint)
        for key, val in ep_index.items():
            if _endpoint_path(key) == path:
                return val
    return None


def _only_token_fields(
    sensitive_fields: list[str],
    description: str,
) -> bool:
    """Return True if the data_leakage issue only concerns token fields."""
    if sensitive_fields:
        return all(f.lower() in _TOKEN_FIELDS for f in sensitive_fields)
    for token_name in _TOKEN_FIELDS:
        if token_name in description:
            return True
    return False
