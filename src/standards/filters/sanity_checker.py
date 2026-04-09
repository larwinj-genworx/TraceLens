"""Layer 4: Deterministic Sanity Check.

Final pass catching logical impossibilities:
- Cannot have "middleware auth covers all" AND "route X missing auth"
- Cannot have "global error handler" AND "route Y missing error handling"
"""

from __future__ import annotations

import logging
from typing import Any

from src.schemas.issues import Issue
from src.standards.evidence_collectors.base import CategoryEvidenceResult
from src.standards.resolver import ResolvedStandard

logger = logging.getLogger(__name__)

_GLOBAL_STYLE_TO_ISSUE_TYPE: dict[str, list[str]] = {
    "middleware_auth": ["missing_auth", "missing_authentication"],
    "session_auth": ["missing_auth"],
    "global_error_handling": [
        "missing_error_handling",
        "missing_error_handling_flow",
    ],
    "middleware_error_handling": [
        "missing_error_handling",
        "missing_error_handling_flow",
    ],
}


def apply_sanity_check(
    issues: list[Issue],
    resolved: ResolvedStandard,
    evidence_results: list[CategoryEvidenceResult],
) -> list[Issue]:
    """Remove logically impossible findings based on global coverage patterns."""
    if not resolved.has_standard():
        return issues

    globally_covered_issue_types: set[str] = set()

    # Check if any strategy implies global coverage
    for strategy_attr in ("auth_strategy", "error_handling_strategy"):
        strategy_val = getattr(resolved, strategy_attr, "")
        covered_types = _GLOBAL_STYLE_TO_ISSUE_TYPE.get(strategy_val, [])
        globally_covered_issue_types.update(covered_types)

    # Verify global coverage through evidence
    evidence_by_category: dict[str, CategoryEvidenceResult] = {
        er.category: er for er in evidence_results
    }

    confirmed_global: set[str] = set()
    for issue_type in globally_covered_issue_types:
        category_map = {
            "missing_auth": "auth_style",
            "missing_authentication": "auth_style",
            "missing_error_handling": "error_handling",
            "missing_error_handling_flow": "error_handling",
        }
        cat = category_map.get(issue_type)
        if cat and cat in evidence_by_category:
            ev = evidence_by_category[cat]
            if ev.overall_status in ("compliant", "partial"):
                has_registration = any(
                    e.status == "compliant" for e in ev.evidence_items
                )
                if has_registration:
                    confirmed_global.add(issue_type)

    # Build endpoint → evidence details map for auth-flow checks
    endpoint_evidence: dict[str, dict[str, Any]] = {}
    for er in evidence_results:
        for ev in er.evidence_items:
            if ev.endpoint:
                endpoint_evidence.setdefault(ev.endpoint, {}).update({
                    "route_intent": None,
                    "category": er.category,
                    "status": ev.status,
                })

    # Also build a route_intent lookup from evidence details
    for er in evidence_results:
        for ev in er.evidence_items:
            if ev.endpoint and ev.details.get("route_intent"):
                endpoint_evidence.setdefault(ev.endpoint, {})["route_intent"] = ev.details["route_intent"]

    filtered: list[Issue] = []
    removed = 0

    for issue in issues:
        # Remove globally covered issues
        if issue.type.lower() in confirmed_global:
            logger.info(
                "sanity_check: removed impossible %s on %s — global coverage confirmed",
                issue.type,
                issue.endpoint or "?",
            )
            removed += 1
            continue

        # Auth-flow endpoints should not get auth_mechanism or authz violations
        if issue.endpoint:
            ep_ev = endpoint_evidence.get(issue.endpoint, {})
            route_intent = ep_ev.get("route_intent")
            # Also check the issue evidence for route_intent
            if not route_intent and hasattr(issue, "evidence") and isinstance(issue.evidence, dict):
                route_intent = issue.evidence.get("route_intent")

            if route_intent == "auth_entry":
                if issue.type.startswith("standards_violation_auth_mechanism"):
                    logger.info(
                        "sanity_check: removed %s on auth_entry endpoint %s",
                        issue.type, issue.endpoint,
                    )
                    removed += 1
                    continue
                if issue.type.startswith("standards_violation_authz_model"):
                    logger.info(
                        "sanity_check: removed %s on auth_entry endpoint %s",
                        issue.type, issue.endpoint,
                    )
                    removed += 1
                    continue

        filtered.append(issue)

    if removed:
        logger.info("sanity_check: removed %d logically impossible issues", removed)

    return filtered
