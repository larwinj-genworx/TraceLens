"""Layer 1.5: Cross-Category Evidence Reconciliation.

Reconciles conflicts between category evidence. For example, if auth_style
evidence says an endpoint is compliant (middleware covers it) but auth_mechanism
evidence says the same endpoint is a violation, this filter checks whether the
mechanism is provided at the middleware level and suppresses the false positive.
"""

from __future__ import annotations

import logging
from typing import Any

from src.schemas.issues import Issue
from src.standards.evidence_collectors.base import CategoryEvidenceResult
from src.standards.resolver import ResolvedStandard

logger = logging.getLogger(__name__)


def apply_cross_category_filter(
    issues: list[Issue],
    evidence_results: list[CategoryEvidenceResult],
    resolved: ResolvedStandard,
) -> list[Issue]:
    """Suppress issues where cross-category evidence indicates compliance."""
    if not resolved.has_standard() or not evidence_results:
        return issues

    evidence_by_category: dict[str, CategoryEvidenceResult] = {
        er.category: er for er in evidence_results
    }

    # Build per-endpoint compliance maps for quick lookups
    compliant_by_category: dict[str, set[str]] = {}
    for cat, ev_result in evidence_by_category.items():
        endpoints: set[str] = set()
        for ev in ev_result.evidence_items:
            if ev.status == "compliant" and ev.endpoint:
                endpoints.add(ev.endpoint)
        compliant_by_category[cat] = endpoints

    filtered: list[Issue] = []
    removed = 0

    for issue in issues:
        should_remove = False

        # Rule 1: auth_style compliant + auth_mechanism violation on same endpoint
        #   → if auth_style shows middleware/DI covers the endpoint, and mechanism
        #     is enforced at middleware level, suppress auth_mechanism violation
        if issue.type.startswith("standards_violation_auth_mechanism"):
            ep = issue.endpoint
            auth_style_compliant = ep and ep in compliant_by_category.get("auth_style", set())
            if auth_style_compliant:
                logger.info(
                    "cross_category: suppressed %s on %s — auth_style is compliant",
                    issue.type, ep,
                )
                should_remove = True

        # Rule 2: ownership_protection violation on admin-only endpoints
        #   → if the endpoint has authz evidence showing admin role enforcement,
        #     suppress ownership violation on global resources
        if issue.type.startswith("standards_violation_ownership"):
            ep = issue.endpoint
            authz_compliant = ep and ep in compliant_by_category.get("authz_model", set())
            if authz_compliant and _is_likely_admin_endpoint(issue):
                logger.info(
                    "cross_category: suppressed %s on %s — authz (admin) covers ownership",
                    issue.type, ep,
                )
                should_remove = True

        # Rule 3: auth_style + auth_mechanism both compliant → suppress any
        #   remaining auth-related mandatory flow issues for that endpoint
        if issue.type in ("missing_auth", "missing_authentication"):
            ep = issue.endpoint
            auth_style_ok = ep and ep in compliant_by_category.get("auth_style", set())
            auth_mech_ok = ep and ep in compliant_by_category.get("auth_mechanism", set())
            if auth_style_ok or auth_mech_ok:
                logger.info(
                    "cross_category: suppressed %s on %s — standards evidence is compliant",
                    issue.type, ep,
                )
                should_remove = True

        if should_remove:
            removed += 1
            continue

        filtered.append(issue)

    if removed:
        logger.info("cross_category_filter: removed %d issues", removed)

    return filtered


def _is_likely_admin_endpoint(issue: Issue) -> bool:
    """Heuristic: check if issue evidence suggests admin-only context."""
    ev = issue.evidence or {}
    endpoint = issue.endpoint or ""
    desc = issue.description or ""
    combined = f"{endpoint} {desc}".lower()
    return any(kw in combined for kw in ("admin", "/admin", "superuser", "staff"))
