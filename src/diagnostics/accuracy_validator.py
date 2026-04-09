"""Post-analysis accuracy validation.

Validates that:
1. Every finding is checked against the correct standard category
2. No endpoint was skipped
3. Evidence chains are complete
4. Issues match the user's declared style
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from src.config.settings import settings
from src.schemas.issues import Issue
from src.standards.evidence_collectors.base import CategoryEvidenceResult
from src.standards.resolver import ResolvedStandard

logger = logging.getLogger(__name__)

_ISSUE_TYPE_TO_CATEGORY: dict[str, str] = {
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


@dataclass
class AccuracyValidationResult:
    """Result of post-analysis accuracy validation."""

    total_issues: int = 0
    validated_issues: int = 0
    style_mismatches: int = 0
    orphan_issues: int = 0
    warnings: list[str] = field(default_factory=list)
    accuracy_score: float = 100.0
    details: list[dict[str, Any]] = field(default_factory=list)
    issue_counts_by_category: dict[str, int] = field(default_factory=dict)
    violation_counts_by_category: dict[str, int] = field(default_factory=dict)
    categories_without_issue_coverage: list[str] = field(default_factory=list)
    file_line_presence_rate: float = 0.0


class AccuracyValidator:
    """Validates analysis accuracy against the declared standard."""

    def __init__(self, resolved: ResolvedStandard) -> None:
        self.resolved = resolved

    def validate(
        self,
        issues: list[Issue],
        evidence_results: list[CategoryEvidenceResult],
    ) -> AccuracyValidationResult:
        result = AccuracyValidationResult(total_issues=len(issues))

        evidence_by_category = {er.category: er for er in evidence_results}
        violation_counts: dict[str, int] = {}
        for category, ev in evidence_by_category.items():
            violation_counts[category] = sum(
                1 for item in ev.evidence_items if item.status == "violation"
            )
        result.violation_counts_by_category = violation_counts

        standards_issue_count = 0
        standards_issue_with_location = 0

        for issue in issues:
            issue_type_lower = issue.type.lower()
            category = _ISSUE_TYPE_TO_CATEGORY.get(issue_type_lower)
            if issue_type_lower.startswith("standards_violation_"):
                stripped = issue_type_lower.removeprefix("standards_violation_")
                category = stripped.split("_", 1)[0] if "_" in stripped else stripped
                # Preserve full category when possible.
                for candidate in evidence_by_category.keys():
                    if stripped.startswith(candidate):
                        category = candidate
                        break

                standards_issue_count += 1
                if issue.file and issue.line is not None:
                    standards_issue_with_location += 1

            if not category:
                result.validated_issues += 1
                continue

            result.issue_counts_by_category[category] = (
                result.issue_counts_by_category.get(category, 0) + 1
            )

            cat_resolution = self.resolved.fastapi.categories.get(category)
            if not cat_resolution and category in (
                "auth_token_storage",
                "http_client",
            ):
                cat_resolution = self.resolved.react.categories.get(category)

            if not cat_resolution:
                result.orphan_issues += 1
                result.details.append({
                    "issue_type": issue.type,
                    "endpoint": issue.endpoint,
                    "problem": f"No standard category '{category}' configured",
                })
                continue

            ev_result = evidence_by_category.get(category)
            if ev_result:
                has_violation_evidence = any(
                    (e.endpoint == issue.endpoint or not e.endpoint)
                    and e.status == "violation"
                    for e in ev_result.evidence_items
                )
                has_compliant_evidence = any(
                    (e.endpoint == issue.endpoint or not e.endpoint)
                    and e.status == "compliant"
                    for e in ev_result.evidence_items
                )

                if has_compliant_evidence and not has_violation_evidence:
                    result.style_mismatches += 1
                    result.details.append({
                        "issue_type": issue.type,
                        "endpoint": issue.endpoint,
                        "problem": "Issue flagged but evidence shows compliant",
                        "category": category,
                        "style": cat_resolution.selected_style,
                    })
                    continue

            result.validated_issues += 1

        if result.total_issues > 0:
            result.accuracy_score = (
                (result.validated_issues / result.total_issues) * 100
            )
        else:
            result.accuracy_score = 100.0

        if standards_issue_count > 0:
            result.file_line_presence_rate = (
                standards_issue_with_location / standards_issue_count
            ) * 100
        else:
            result.file_line_presence_rate = 100.0

        missing_coverage = [
            category
            for category, violations in result.violation_counts_by_category.items()
            if violations > 0 and result.issue_counts_by_category.get(category, 0) == 0
        ]
        result.categories_without_issue_coverage = sorted(missing_coverage)

        if result.style_mismatches > 0:
            result.warnings.append(
                f"{result.style_mismatches} issues conflict with standards evidence."
            )
        if result.orphan_issues > 0:
            result.warnings.append(
                f"{result.orphan_issues} issues reference unconfigured categories."
            )
        if result.categories_without_issue_coverage:
            result.warnings.append(
                "Violations were detected but not surfaced as issues for categories: "
                + ", ".join(result.categories_without_issue_coverage)
            )
        if result.file_line_presence_rate < 95:
            result.warnings.append(
                f"Only {result.file_line_presence_rate:.1f}% of standards issues include file+line metadata."
            )

        logger.info(
            "accuracy_validator: total=%d validated=%d mismatches=%d orphans=%d score=%.1f%% line_rate=%.1f%%",
            result.total_issues,
            result.validated_issues,
            result.style_mismatches,
            result.orphan_issues,
            result.accuracy_score,
            result.file_line_presence_rate,
        )

        return result

    def dump_trace(
        self,
        job_id: str,
        result: AccuracyValidationResult,
    ) -> None:
        """Write accuracy trace to disk if tracing is enabled."""
        if not settings.evidence_trace_enabled:
            return

        trace_dir = settings.evidence_trace_dir / job_id
        trace_dir.mkdir(parents=True, exist_ok=True)
        filepath = trace_dir / "accuracy_validation.json"

        payload = {
            "_meta": {
                "job_id": job_id,
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "accuracy_score": result.accuracy_score,
            "total_issues": result.total_issues,
            "validated_issues": result.validated_issues,
            "style_mismatches": result.style_mismatches,
            "orphan_issues": result.orphan_issues,
            "warnings": result.warnings,
            "details": result.details,
            "issue_counts_by_category": result.issue_counts_by_category,
            "violation_counts_by_category": result.violation_counts_by_category,
            "categories_without_issue_coverage": result.categories_without_issue_coverage,
            "file_line_presence_rate": result.file_line_presence_rate,
        }

        try:
            filepath.write_text(
                json.dumps(payload, indent=2, ensure_ascii=False),
                encoding="utf-8",
            )
            logger.info("accuracy trace written: %s", filepath)
        except Exception:
            logger.exception("accuracy trace write failed: %s", filepath)
