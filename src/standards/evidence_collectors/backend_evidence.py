"""Evidence collectors for backend quality categories: validation, error handling,
persistence, architecture, and other FastAPI-specific concerns."""

from __future__ import annotations

import logging
import os
from typing import Any

from src.schemas.internal import BackendEndpoint, StaticAnalysisResult
from src.standards.evidence_collectors.base import CategoryEvidenceResult, Evidence
from src.standards.resolver import ResolvedStandard

logger = logging.getLogger(__name__)


def _endpoint_key(ep: BackendEndpoint) -> str:
    return f"{ep.method} {ep.path}"


def _has_any_marker(text_sources: list[str], markers: list[str]) -> bool:
    lower_sources = [s.lower() for s in text_sources]
    for marker in markers:
        ml = marker.lower()
        if any(ml in source for source in lower_sources):
            return True
    return False


def collect_validation_evidence(
    resolved: ResolvedStandard,
    static_results: dict[str, StaticAnalysisResult],
) -> CategoryEvidenceResult:
    """Check request validation coverage on write endpoints."""

    style = resolved.fastapi.get_style("request_validation")
    markers = resolved.validation_markers
    strategy = resolved.fastapi.get_strategy("request_validation")
    result = CategoryEvidenceResult(
        category="request_validation",
        declared_style=style,
        overall_status="compliant",
    )

    write_methods = {"POST", "PUT", "PATCH"}

    for repo_name, static in static_results.items():
        for ep in static.backend_endpoints:
            if ep.method.upper() not in write_methods:
                continue

            if not ep.expects_request_body:
                result.add(Evidence(
                    category="request_validation",
                    style=style,
                    status="compliant",
                    file=ep.file,
                    line=ep.line,
                    endpoint=_endpoint_key(ep),
                    service=repo_name,
                    confidence=0.92,
                    message=f"No request body expected — path/query params validated by framework",
                ))
                continue

            if strategy == "pydantic_validation" or style == "pydantic_models":
                if ep.request_schema or ep.request_fields:
                    result.add(Evidence(
                        category="request_validation",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.93,
                        message=f"Pydantic request model found on {_endpoint_key(ep)}",
                    ))
                else:
                    result.add(Evidence(
                        category="request_validation",
                        style=style,
                        status="violation",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.88,
                        message=f"No Pydantic request model on write endpoint {_endpoint_key(ep)}",
                    ))
            else:
                text_pool = ep.call_refs + ep.string_refs + ep.dependencies
                if _has_any_marker(text_pool, markers):
                    result.add(Evidence(
                        category="request_validation",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.85,
                        message=f"Validation marker found on {_endpoint_key(ep)}",
                    ))
                else:
                    result.add(Evidence(
                        category="request_validation",
                        style=style,
                        status="violation",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.80,
                        message=f"No validation on write endpoint {_endpoint_key(ep)}",
                    ))

    result.compute_status()
    return result


def collect_response_contract_evidence(
    resolved: ResolvedStandard,
    static_results: dict[str, StaticAnalysisResult],
) -> CategoryEvidenceResult:
    """Check response contract coverage."""

    style = resolved.fastapi.get_style("response_contract")
    markers = resolved.fastapi.get_markers("response_contract")
    strategy = resolved.fastapi.get_strategy("response_contract")
    result = CategoryEvidenceResult(
        category="response_contract",
        declared_style=style,
        overall_status="compliant",
    )

    data_methods = {"GET", "POST", "PUT", "PATCH"}

    for repo_name, static in static_results.items():
        for ep in static.backend_endpoints:
            if ep.method.upper() not in data_methods:
                continue

            if ep.returns_file_response:
                result.add(Evidence(
                    category="response_contract",
                    style=style,
                    status="compliant",
                    file=ep.file,
                    line=ep.line,
                    endpoint=_endpoint_key(ep),
                    service=repo_name,
                    confidence=0.93,
                    message=f"Binary file response — Pydantic response model not applicable",
                ))
                continue
            if ep.status_code_literal == 204:
                result.add(Evidence(
                    category="response_contract",
                    style=style,
                    status="compliant",
                    file=ep.file,
                    line=ep.line,
                    endpoint=_endpoint_key(ep),
                    service=repo_name,
                    confidence=0.95,
                    message=f"204 No Content — no response body",
                ))
                continue

            if strategy == "response_model_contract" or style == "response_model":
                if ep.response_schema or ep.response_fields:
                    result.add(Evidence(
                        category="response_contract",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.92,
                        message=f"Response model found on {_endpoint_key(ep)}",
                    ))
                else:
                    result.add(Evidence(
                        category="response_contract",
                        style=style,
                        status="violation",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.85,
                        message=f"No response model on {_endpoint_key(ep)}",
                    ))
            else:
                text_pool = ep.call_refs + ep.string_refs
                if _has_any_marker(text_pool, markers):
                    result.add(Evidence(
                        category="response_contract",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.82,
                        message=f"Response contract marker found on {_endpoint_key(ep)}",
                    ))
                else:
                    result.add(Evidence(
                        category="response_contract",
                        style=style,
                        status="violation",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.78,
                        message=f"No response contract on {_endpoint_key(ep)}",
                    ))

    result.compute_status()
    return result


def collect_error_handling_evidence(
    resolved: ResolvedStandard,
    static_results: dict[str, StaticAnalysisResult],
) -> CategoryEvidenceResult:
    """Check error handling coverage using the declared strategy."""

    style = resolved.fastapi.get_style("error_handling")
    markers = resolved.error_handling_markers
    strategy = resolved.fastapi.get_strategy("error_handling")
    result = CategoryEvidenceResult(
        category="error_handling",
        declared_style=style,
        overall_status="compliant",
    )

    for repo_name, static in static_results.items():
        facts = static.fastapi_facts

        if strategy in (
            "global_error_handling",
            "middleware_error_handling",
            "hybrid_error_handling",
        ):
            handler_found = _has_any_marker(
                facts.exception_handler_refs + facts.middleware_refs,
                markers,
            )
            if handler_found:
                for ep in static.backend_endpoints:
                    result.add(Evidence(
                        category="error_handling",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.90,
                        message=f"Global error handler covers {_endpoint_key(ep)}",
                    ))
            else:
                result.add(Evidence(
                    category="error_handling",
                    style=style,
                    status="violation",
                    service=repo_name,
                    confidence=0.85,
                    message="Declared global error handling but no matching handler found.",
                    details={"expected_markers": markers},
                ))

        elif strategy == "per_route_error_handling":
            for ep in static.backend_endpoints:
                if ep.has_try_except:
                    result.add(Evidence(
                        category="error_handling",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.88,
                        message=f"Try/except found in {_endpoint_key(ep)}",
                    ))
                else:
                    result.add(Evidence(
                        category="error_handling",
                        style=style,
                        status="violation",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.82,
                        message=f"No try/except in {_endpoint_key(ep)}",
                    ))

        elif strategy == "custom_exception_error_handling":
            text_pool = facts.module_call_refs + facts.exception_handler_refs
            if _has_any_marker(text_pool, markers):
                result.add(Evidence(
                    category="error_handling",
                    style=style,
                    status="compliant",
                    service=repo_name,
                    confidence=0.85,
                    message="Custom exception class hierarchy detected.",
                ))
            else:
                result.add(Evidence(
                    category="error_handling",
                    style=style,
                    status="violation",
                    service=repo_name,
                    confidence=0.80,
                    message="Declared custom exception classes but none found.",
                ))

    result.compute_status()
    return result


def collect_folder_structure_evidence(
    resolved: ResolvedStandard,
    repo_paths: dict[str, str],
    repo_types: dict[str, str] | None = None,
) -> CategoryEvidenceResult:
    """Validate actual folder structure against declared expectations."""

    result = CategoryEvidenceResult(
        category="folder_structure",
        declared_style="declared",
        overall_status="compliant",
    )

    for stack_key, stack in [("fastapi", resolved.fastapi), ("react", resolved.react)]:
        for role_id, expected_path in stack.folder_expectations.items():
            if not expected_path:
                continue
            for repo_name, repo_root in repo_paths.items():
                if not _repo_supports_stack(repo_name, stack_key, repo_types):
                    continue
                full_path = os.path.join(repo_root, expected_path)
                if os.path.isdir(full_path):
                    result.add(Evidence(
                        category="folder_structure",
                        style=f"{stack_key}:{role_id}",
                        status="compliant",
                        file=expected_path,
                        service=repo_name,
                        confidence=0.95,
                        message=f"Folder '{expected_path}' exists for {role_id} ({stack_key})",
                    ))
                else:
                    result.add(Evidence(
                        category="folder_structure",
                        style=f"{stack_key}:{role_id}",
                        status="violation",
                        file=expected_path,
                        service=repo_name,
                        confidence=0.90,
                        message=f"Expected folder '{expected_path}' for {role_id} ({stack_key}) not found",
                        details={"reason": "folder_path_missing"},
                    ))

    result.compute_status()
    return result


def _repo_supports_stack(
    repo_name: str,
    stack_key: str,
    repo_types: dict[str, str] | None,
) -> bool:
    if not repo_types:
        return True
    hint = repo_types.get(repo_name, "").lower()
    if stack_key == "fastapi":
        return hint in {"backend", "mixed"}
    return hint in {"frontend", "mixed"}
