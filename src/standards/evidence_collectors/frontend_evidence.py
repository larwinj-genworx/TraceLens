"""Evidence collectors for React frontend categories."""

from __future__ import annotations

import logging
from typing import Any

from src.schemas.internal import ClientStorageIssue, FrontendCall, StaticAnalysisResult
from src.standards.evidence_collectors.base import CategoryEvidenceResult, Evidence
from src.standards.resolver import ResolvedStandard

logger = logging.getLogger(__name__)


def _has_any_marker(text_sources: list[str], markers: list[str]) -> bool:
    lower_sources = [s.lower() for s in text_sources]
    for marker in markers:
        ml = marker.lower()
        if any(ml in source for source in lower_sources):
            return True
    return False


def collect_token_storage_evidence(
    resolved: ResolvedStandard,
    static_results: dict[str, StaticAnalysisResult],
) -> CategoryEvidenceResult:
    """Check auth token storage compliance against the declared style."""

    style = resolved.token_storage_style
    strategy = resolved.react.get_strategy("auth_token_storage")
    result = CategoryEvidenceResult(
        category="auth_token_storage",
        declared_style=style,
        overall_status="compliant",
    )

    if not style:
        result.overall_status = "not_applicable"
        return result

    for repo_name, static in static_results.items():
        for issue in static.client_storage_issues:
            key_lower = issue.key.lower()
            is_auth_related = any(
                kw in key_lower
                for kw in ("token", "auth", "jwt", "access", "refresh", "session")
            )
            if not is_auth_related:
                continue

            if strategy == "httponly_cookie_storage" or style == "httponly_cookie":
                if issue.storage_type in ("localStorage", "sessionStorage"):
                    result.add(Evidence(
                        category="auth_token_storage",
                        style=style,
                        status="violation",
                        file=issue.file,
                        line=issue.line,
                        service=repo_name,
                        confidence=0.92,
                        message=f"Auth token stored in {issue.storage_type} instead of HTTP-only cookie (key: {issue.key})",
                        details={"storage_type": issue.storage_type, "key": issue.key},
                    ))

            elif strategy == "localstorage_storage" or style == "localstorage":
                if issue.storage_type == "localStorage":
                    result.add(Evidence(
                        category="auth_token_storage",
                        style=style,
                        status="compliant",
                        file=issue.file,
                        line=issue.line,
                        service=repo_name,
                        confidence=0.88,
                        message=f"Token stored in localStorage as declared (key: {issue.key})",
                    ))
                elif issue.storage_type == "sessionStorage":
                    result.add(Evidence(
                        category="auth_token_storage",
                        style=style,
                        status="partial",
                        file=issue.file,
                        line=issue.line,
                        service=repo_name,
                        confidence=0.80,
                        message=f"Token stored in sessionStorage but localStorage was declared (key: {issue.key})",
                    ))

            elif strategy == "sessionstorage_storage" or style == "sessionstorage":
                if issue.storage_type == "sessionStorage":
                    result.add(Evidence(
                        category="auth_token_storage",
                        style=style,
                        status="compliant",
                        file=issue.file,
                        line=issue.line,
                        service=repo_name,
                        confidence=0.88,
                        message=f"Token stored in sessionStorage as declared (key: {issue.key})",
                    ))
                elif issue.storage_type == "localStorage":
                    result.add(Evidence(
                        category="auth_token_storage",
                        style=style,
                        status="violation",
                        file=issue.file,
                        line=issue.line,
                        service=repo_name,
                        confidence=0.85,
                        message=f"Token stored in localStorage but sessionStorage was declared (key: {issue.key})",
                    ))

            elif strategy in ("memory_storage", "auth_provider_storage") or style in ("memory_only", "auth_provider"):
                if issue.storage_type in ("localStorage", "sessionStorage"):
                    result.add(Evidence(
                        category="auth_token_storage",
                        style=style,
                        status="violation",
                        file=issue.file,
                        line=issue.line,
                        service=repo_name,
                        confidence=0.88,
                        message=f"Token persisted in {issue.storage_type} but in-memory/provider storage was declared (key: {issue.key})",
                    ))

    result.compute_status()
    return result


def collect_http_client_evidence(
    resolved: ResolvedStandard,
    static_results: dict[str, StaticAnalysisResult],
) -> CategoryEvidenceResult:
    """Check that frontend uses the declared HTTP client consistently."""

    style = resolved.http_client_style
    markers = resolved.react.get_markers("http_client")
    result = CategoryEvidenceResult(
        category="http_client",
        declared_style=style,
        overall_status="compliant",
    )

    if not style:
        result.overall_status = "not_applicable"
        return result

    for repo_name, static in static_results.items():
        for call in static.frontend_calls:
            call_file = call.file.lower()
            raw = call.raw_url.lower()

            markers_matched = _has_any_marker(
                [call.raw_url, call.file],
                markers,
            )

            if markers_matched:
                result.add(Evidence(
                    category="http_client",
                    style=style,
                    status="compliant",
                    file=call.file,
                    line=call.line,
                    service=repo_name,
                    confidence=0.85,
                    message=f"HTTP call in {call.file} uses declared client style",
                ))

    if not result.evidence_items:
        result.overall_status = "not_applicable"
        result.summary = "No frontend calls detected to verify HTTP client usage."

    result.compute_status()
    return result
