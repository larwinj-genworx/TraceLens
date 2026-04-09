"""5-layer false positive elimination pipeline.

Layer 1:   Style-aware filtering (dismiss issues contradicted by declared styles)
Layer 1.5: Cross-category reconciliation (suppress cross-category contradictions)
Layer 2:   Cross-evidence verification (dismiss issues contradicted by evidence)
Layer 3:   LLM verification (handled by cross_reviewer in the LangGraph)
Layer 4:   Deterministic sanity check (catch logical impossibilities)
"""

from __future__ import annotations

import logging
from typing import Any

from src.schemas.issues import Issue
from src.standards.evidence_collectors.base import CategoryEvidenceResult
from src.standards.filters.cross_category_filter import apply_cross_category_filter
from src.standards.filters.cross_verifier import apply_cross_verification
from src.standards.filters.sanity_checker import apply_sanity_check
from src.standards.filters.style_filter import apply_style_filter
from src.standards.resolver import ResolvedStandard

logger = logging.getLogger(__name__)


def run_false_positive_pipeline(
    issues: list[Issue],
    resolved: ResolvedStandard,
    evidence_results: list[CategoryEvidenceResult],
) -> list[Issue]:
    """Run the complete 5-layer false positive elimination pipeline.

    Layer 3 (LLM verification) runs inside the LangGraph cross_reviewer node
    via standards_context injection and is NOT repeated here.
    """
    original_count = len(issues)

    # Layer 1: Style-aware filtering (with cross-category evidence)
    issues = apply_style_filter(issues, resolved, evidence_results=evidence_results)
    after_l1 = len(issues)

    # Layer 1.5: Cross-category evidence reconciliation
    issues = apply_cross_category_filter(issues, evidence_results, resolved)
    after_l15 = len(issues)

    # Layer 2: Cross-evidence verification
    issues = apply_cross_verification(issues, evidence_results, resolved)
    after_l2 = len(issues)

    # Layer 4: Deterministic sanity check
    issues = apply_sanity_check(issues, resolved, evidence_results)
    after_l4 = len(issues)

    logger.info(
        "fp_pipeline: %d -> L1:%d -> L1.5:%d -> L2:%d -> L4:%d (removed %d total)",
        original_count,
        after_l1,
        after_l15,
        after_l2,
        after_l4,
        original_count - after_l4,
    )

    return issues
