"""Layer 2: Cross-Evidence Verification.

Every issue must be backed by evidence. Issues contradicted by the
standards evidence get demoted or removed. Issues with multiple
confirming sources get boosted confidence.
"""

from __future__ import annotations

import logging
from typing import Any

from src.schemas.issues import ConfidenceBand, Issue
from src.standards.evidence_collectors.base import CategoryEvidenceResult
from src.standards.resolver import ResolvedStandard

logger = logging.getLogger(__name__)

_ISSUE_TO_CATEGORY: dict[str, str] = {
    "missing_auth": "auth_style",
    "missing_authentication": "auth_style",
    "missing_authz": "authz_model",
    "missing_authz_flow": "authz_model",
    "missing_ownership_check": "ownership_protection",
    "missing_validation": "request_validation",
    "missing_response_contract": "response_contract",
    "missing_response_contract_flow": "response_contract",
    "missing_error_handling": "error_handling",
    "missing_error_handling_flow": "error_handling",
    "insecure_token_storage": "auth_token_storage",
}


def apply_cross_verification(
    issues: list[Issue],
    evidence_results: list[CategoryEvidenceResult],
    resolved: ResolvedStandard,
) -> list[Issue]:
    """Verify issues against collected standards evidence.

    Issues contradicted by evidence are removed.
    Issues confirmed by evidence get boosted confidence.
    """
    if not evidence_results:
        return issues

    evidence_by_category: dict[str, CategoryEvidenceResult] = {
        er.category: er for er in evidence_results
    }

    compliant_endpoints: dict[str, set[str]] = {}
    for cat, ev_result in evidence_by_category.items():
        compliant_eps: set[str] = set()
        for ev in ev_result.evidence_items:
            if ev.status == "compliant" and ev.endpoint:
                compliant_eps.add(ev.endpoint)
        compliant_endpoints[cat] = compliant_eps

    filtered: list[Issue] = []
    removed = 0
    boosted = 0

    for issue in issues:
        issue_type_lower = issue.type.lower()
        category = _ISSUE_TO_CATEGORY.get(issue_type_lower)

        if category and category in compliant_endpoints:
            ep = issue.endpoint
            if ep and ep in compliant_endpoints[category]:
                logger.info(
                    "cross_verifier: removed %s on %s — standards evidence shows compliant",
                    issue.type,
                    ep,
                )
                removed += 1
                continue

        if category and category in evidence_by_category:
            ev_result = evidence_by_category[category]
            if ev_result.overall_status == "compliant":
                logger.info(
                    "cross_verifier: removed %s — category %s is fully compliant",
                    issue.type,
                    category,
                )
                removed += 1
                continue

            violation_endpoints: set[str] = set()
            for ev in ev_result.evidence_items:
                if ev.status == "violation" and ev.endpoint:
                    violation_endpoints.add(ev.endpoint)

            if issue.endpoint and issue.endpoint in violation_endpoints:
                issue.confidence = min(1.0, issue.confidence + 0.1)
                if issue.confidence >= 0.9:
                    issue.confidence_band = ConfidenceBand.CORROBORATED
                boosted += 1

        filtered.append(issue)

    if removed or boosted:
        logger.info(
            "cross_verifier: removed=%d boosted=%d from %d total",
            removed,
            boosted,
            len(issues),
        )

    return filtered
