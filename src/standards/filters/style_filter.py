"""Layer 1: Style-Aware Filtering.

Automatically dismisses issues that contradict the user's declared styles.
For example, if the user declared global_middleware auth, missing_auth on
individual routes are dismissed because the middleware covers them.
"""

from __future__ import annotations

import logging
from typing import Any

from src.schemas.issues import Issue
from src.standards.resolver import ResolvedStandard

logger = logging.getLogger(__name__)


_STYLE_DISMISSAL_RULES: list[dict[str, Any]] = [
    {
        "category": "auth_style",
        "style": "global_middleware",
        "dismiss_types": ["missing_auth", "missing_authentication"],
        "reason": "Global auth middleware covers all non-excluded routes.",
    },
    {
        "category": "auth_style",
        "style": "session_based",
        "dismiss_types": ["missing_auth"],
        "reason": "Session middleware covers all authenticated routes.",
    },
    {
        "category": "error_handling",
        "style": "global_exception_handler",
        "dismiss_types": ["missing_error_handling", "missing_error_handling_flow"],
        "reason": "Global exception handler covers all routes.",
    },
    {
        "category": "error_handling",
        "style": "centralized_middleware",
        "dismiss_types": ["missing_error_handling", "missing_error_handling_flow"],
        "reason": "Centralized error middleware covers all routes.",
    },
    {
        "category": "auth_token_storage",
        "style": "httponly_cookie_storage",
        "dismiss_types": ["insecure_token_storage"],
        "reason": "HTTP-only cookies are the declared storage mechanism.",
    },
    {
        "category": "auth_style",
        "style": "dependency_injection",
        "dismiss_types": [
            "standards_violation_auth_mechanism_jwt_bearer",
            "standards_violation_auth_mechanism_session",
        ],
        "cross_category": "auth_mechanism",
        "reason": "Auth mechanism enforced via middleware; auth style uses DI for route access.",
    },
]


def apply_style_filter(
    issues: list[Issue],
    resolved: ResolvedStandard,
    evidence_results: list[Any] | None = None,
) -> list[Issue]:
    """Remove issues contradicted by the user's declared standards.

    Returns a new list with contradicted issues removed.
    """
    if not resolved.has_standard():
        return issues

    dismiss_types: set[str] = set()
    reasons: dict[str, str] = {}

    # Build evidence-by-category index for cross-category rules
    evidence_by_cat: dict[str, Any] = {}
    if evidence_results:
        for er in evidence_results:
            evidence_by_cat[er.category] = er

    for rule in _STYLE_DISMISSAL_RULES:
        cat = rule["category"]
        style_val = rule["style"]

        actual_style = resolved.fastapi.get_style(cat)
        if not actual_style:
            actual_style = resolved.react.get_style(cat)

        if actual_style != style_val:
            continue

        # Cross-category check: only dismiss if the cross-category evidence is compliant
        cross_cat = rule.get("cross_category")
        if cross_cat and evidence_by_cat:
            cross_ev = evidence_by_cat.get(cross_cat)
            if cross_ev and cross_ev.overall_status not in ("compliant", "partial"):
                continue

        for dtype in rule["dismiss_types"]:
            dismiss_types.add(dtype)
            reasons[dtype] = rule["reason"]

    if not dismiss_types:
        return issues

    filtered: list[Issue] = []
    removed = 0

    for issue in issues:
        issue_type_lower = issue.type.lower()
        if issue_type_lower in dismiss_types:
            logger.info(
                "style_filter: dismissed %s on %s — %s",
                issue.type,
                issue.endpoint or "?",
                reasons.get(issue_type_lower, "style override"),
            )
            removed += 1
            continue
        filtered.append(issue)

    if removed:
        logger.info("style_filter: removed %d issues", removed)

    return filtered
