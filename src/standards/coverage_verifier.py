"""Coverage completeness verification.

After all analysis completes, verify that every discovered endpoint was
checked against every applicable category from the standard.
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from src.schemas.internal import StaticAnalysisResult
from src.standards.coverage_tracker import CoverageMatrix, EndpointCoverageTracker
from src.standards.evidence_collectors.base import CategoryEvidenceResult
from src.standards.resolver import ResolvedStandard

logger = logging.getLogger(__name__)


@dataclass
class CoverageVerificationResult:
    """Final coverage verification output."""

    total_endpoints: int = 0
    total_frontend_calls: int = 0
    total_category_checks: int = 0
    checked_count: int = 0
    unchecked_count: int = 0
    coverage_pct: float = 100.0
    gaps: list[dict[str, str]] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    passed: bool = True
    stack_totals: dict[str, int] = field(default_factory=dict)
    stack_unchecked: dict[str, int] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_endpoints": self.total_endpoints,
            "total_frontend_calls": self.total_frontend_calls,
            "total_category_checks": self.total_category_checks,
            "checked": self.checked_count,
            "unchecked": self.unchecked_count,
            "coverage_pct": round(self.coverage_pct, 1),
            "gaps": self.gaps,
            "warnings": self.warnings,
            "passed": self.passed,
            "stack_totals": self.stack_totals,
            "stack_unchecked": self.stack_unchecked,
        }


class CoverageVerifier:
    """Verifies that analysis covered all endpoints and categories."""

    def __init__(self, resolved: ResolvedStandard) -> None:
        self.resolved = resolved

    def verify(
        self,
        static_results: dict[str, StaticAnalysisResult],
        evidence_results: list[CategoryEvidenceResult],
        coverage_matrix: CoverageMatrix | None = None,
    ) -> CoverageVerificationResult:
        result = CoverageVerificationResult()

        total_be = 0
        total_fe = 0
        for static in static_results.values():
            total_be += len(static.backend_endpoints)
            total_fe += len(static.frontend_calls)

        result.total_endpoints = total_be
        result.total_frontend_calls = total_fe

        if coverage_matrix:
            result.total_category_checks = coverage_matrix.total_count
            result.checked_count = coverage_matrix.total_count - coverage_matrix.unchecked_count
            result.unchecked_count = coverage_matrix.unchecked_count
            result.coverage_pct = coverage_matrix.coverage_pct
            result.gaps = [
                {
                    "endpoint": c.endpoint,
                    "service": c.service,
                    "category": c.category,
                    "stack": c.stack,
                }
                for c in coverage_matrix.cells
                if not c.checked
            ]
            for cell in coverage_matrix.cells:
                result.stack_totals[cell.stack] = result.stack_totals.get(cell.stack, 0) + 1
                if not cell.checked:
                    result.stack_unchecked[cell.stack] = (
                        result.stack_unchecked.get(cell.stack, 0) + 1
                    )
        else:
            result.total_category_checks = 0
            result.checked_count = 0

        if total_be == 0:
            result.warnings.append("No backend endpoints were discovered in the project.")

        categories_with_evidence = {er.category for er in evidence_results}
        expected_categories = set(self.resolved.fastapi.categories.keys()) | set(
            self.resolved.react.categories.keys()
        )
        if self.resolved.fastapi.folder_expectations or self.resolved.react.folder_expectations:
            expected_categories.add("folder_structure")
        missing_categories = expected_categories - categories_with_evidence
        if missing_categories:
            result.warnings.append(
                f"No evidence collected for categories: {', '.join(sorted(missing_categories))}"
            )

        zero_evidence = [
            er.category
            for er in evidence_results
            if not er.evidence_items and er.overall_status != "not_applicable"
        ]
        if zero_evidence:
            result.warnings.append(
                f"Categories with no evidence found: {', '.join(zero_evidence)}"
            )

        if result.unchecked_count > 0:
            result.passed = False
            result.warnings.append(
                f"{result.unchecked_count} endpoint-category pairs were not checked."
            )

        folder_result = next(
            (item for item in evidence_results if item.category == "folder_structure"),
            None,
        )
        if folder_result and folder_result.overall_status in {"non_compliant", "partial"}:
            result.passed = False
            result.warnings.append(
                "Folder structure template check did not fully pass."
            )

        for stack, total in result.stack_totals.items():
            if total <= 0:
                continue
            unchecked = result.stack_unchecked.get(stack, 0)
            if unchecked > 0:
                result.warnings.append(
                    f"{stack} stack has {unchecked}/{total} unchecked coverage rows."
                )

        logger.info(
            "coverage_verifier: endpoints=%d fe_calls=%d coverage=%.1f%% gaps=%d passed=%s",
            total_be,
            total_fe,
            result.coverage_pct,
            len(result.gaps),
            result.passed,
        )

        return result
