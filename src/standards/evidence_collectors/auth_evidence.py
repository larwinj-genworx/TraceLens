"""Evidence collectors for authentication and authorization categories."""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

from src.schemas.internal import BackendEndpoint, FastAPIGlobalFacts, StaticAnalysisResult
from src.standards.evidence_collectors.base import CategoryEvidenceResult, Evidence
from src.standards.resolver import ResolvedStandard

if TYPE_CHECKING:
    from src.standards.marker_registry import MarkerRegistry

logger = logging.getLogger(__name__)

_PUBLIC_PATHS = frozenset({
    "/health", "/healthz", "/status", "/docs", "/redoc", "/openapi",
    "/openapi.json", "/metrics", "/readiness", "/liveness", "/ping",
    "/login", "/signup", "/register", "/auth/login", "/auth/register",
    "/auth/signup", "/token/refresh", "/password/reset",
    "/auth/refresh", "/auth/logout", "/auth/forgot-password",
    "/auth/reset-password", "/auth/change-password", "/auth/verify",
})

# Module-level registry instance set during collection
_active_registry: MarkerRegistry | None = None


def _is_public_path(path: str) -> bool:
    if _active_registry and _active_registry.is_public_path(path):
        return True
    normalized = path.lower().rstrip("/")
    return normalized in _PUBLIC_PATHS or any(
        normalized.startswith(p) for p in ("/health", "/docs", "/openapi", "/metrics")
    )


def _endpoint_key(ep: BackendEndpoint) -> str:
    return f"{ep.method} {ep.path}"


def _has_any_marker(text_sources: list[str], markers: list[str]) -> bool:
    lower_sources = [s.lower() for s in text_sources]
    for marker in markers:
        ml = marker.lower()
        if any(ml in source for source in lower_sources):
            return True
    return False


def _uses_dependency_injection(endpoint: BackendEndpoint) -> bool:
    if endpoint.dependencies:
        return True
    dep_tokens = endpoint.call_refs + endpoint.decorators
    lower_tokens = " ".join(dep_tokens).lower()
    return "depends" in lower_tokens or "security(" in lower_tokens


def collect_auth_evidence(
    resolved: ResolvedStandard,
    static_results: dict[str, StaticAnalysisResult],
) -> CategoryEvidenceResult:
    """Collect authentication evidence based on the declared auth style."""

    style = resolved.auth_style
    markers = resolved.auth_markers
    result = CategoryEvidenceResult(
        category="auth_style",
        declared_style=style,
        overall_status="compliant",
    )

    if style == "none":
        result.overall_status = "not_applicable"
        result.summary = "Authentication is declared as not applicable."
        return result

    strategy = resolved.auth_strategy

    for repo_name, static in static_results.items():
        facts = static.fastapi_facts

        if strategy == "middleware_auth":
            middleware_found = _has_any_marker(facts.middleware_refs, markers)
            if middleware_found:
                for ep in static.backend_endpoints:
                    if _is_public_path(ep.path):
                        continue
                    result.add(Evidence(
                        category="auth_style",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.92,
                        message=f"Global auth middleware covers endpoint {_endpoint_key(ep)}",
                        details={"middleware_refs": facts.middleware_refs},
                    ))
            else:
                result.add(Evidence(
                    category="auth_style",
                    style=style,
                    status="violation",
                    service=repo_name,
                    confidence=0.85,
                    message="Declared middleware auth but no matching middleware registration found.",
                    details={"middleware_refs": facts.middleware_refs, "expected_markers": markers},
                ))

        elif strategy == "dep_injection_auth":
            # Detect if repo also has auth middleware (hybrid pattern)
            mw_analysis = facts.auth_middleware_analysis
            has_auth_middleware = bool(
                mw_analysis and mw_analysis.mechanism != "unknown"
            )

            for ep in static.backend_endpoints:
                if _is_public_path(ep.path):
                    continue
                if ep.route_intent in ("public_meta", "auth_entry"):
                    continue

                text_pool = ep.dependencies + ep.call_refs + ep.decorators
                has_di = _has_any_marker(text_pool, markers) or _uses_dependency_injection(ep)

                # Also accept AST-classified auth dependencies
                has_semantic_auth = any(
                    dc.startswith("auth") for dc in ep.dep_classifications
                )

                # Hybrid: middleware covers auth even without per-route DI
                mw_covers = False
                if has_auth_middleware and not has_di and not has_semantic_auth:
                    ep_path_lower = ep.path.lower()
                    excluded = False
                    if mw_analysis and mw_analysis.public_paths:
                        for pub in mw_analysis.public_paths:
                            if pub.lower() in ep_path_lower:
                                excluded = True
                                break
                    if not excluded:
                        mw_covers = True

                if has_di or has_semantic_auth:
                    result.add(Evidence(
                        category="auth_style",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.93,
                        message=f"Auth dependency found on {_endpoint_key(ep)}",
                    ))
                elif mw_covers:
                    result.add(Evidence(
                        category="auth_style",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.88,
                        message=f"Auth middleware covers {_endpoint_key(ep)} (hybrid DI+middleware pattern)",
                        details={"middleware": mw_analysis.middleware_name if mw_analysis else ""},
                    ))
                else:
                    result.add(Evidence(
                        category="auth_style",
                        style=style,
                        status="violation",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.88,
                        message=f"No auth dependency on protected endpoint {_endpoint_key(ep)}",
                        details={"deps": ep.dependencies, "expected_markers": markers},
                    ))

        elif strategy == "decorator_auth":
            for ep in static.backend_endpoints:
                if _is_public_path(ep.path):
                    continue
                if ep.route_intent in ("public_meta", "auth_entry"):
                    continue
                if _has_any_marker(ep.decorators, markers):
                    result.add(Evidence(
                        category="auth_style",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.91,
                        message=f"Auth decorator found on {_endpoint_key(ep)}",
                    ))
                else:
                    result.add(Evidence(
                        category="auth_style",
                        style=style,
                        status="violation",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.85,
                        message=f"No auth decorator on protected endpoint {_endpoint_key(ep)}",
                    ))

        elif strategy == "service_auth":
            for ep in static.backend_endpoints:
                if _is_public_path(ep.path):
                    continue
                if ep.route_intent in ("public_meta", "auth_entry"):
                    continue
                text_pool = ep.call_refs + ep.string_refs + ep.dependencies
                if _has_any_marker(text_pool, markers):
                    result.add(Evidence(
                        category="auth_style",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.85,
                        message=f"Auth service call found in {_endpoint_key(ep)}",
                    ))
                else:
                    result.add(Evidence(
                        category="auth_style",
                        style=style,
                        status="violation",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.80,
                        message=f"No auth service call in protected endpoint {_endpoint_key(ep)}",
                    ))

        elif strategy == "session_auth":
            session_middleware = _has_any_marker(facts.middleware_refs, markers)
            for ep in static.backend_endpoints:
                if _is_public_path(ep.path):
                    continue
                if ep.route_intent in ("public_meta", "auth_entry"):
                    continue
                text_pool = ep.dependencies + ep.call_refs + facts.middleware_refs
                if session_middleware or _has_any_marker(text_pool, markers):
                    result.add(Evidence(
                        category="auth_style",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.88,
                        message=f"Session auth covers {_endpoint_key(ep)}",
                    ))
                else:
                    result.add(Evidence(
                        category="auth_style",
                        style=style,
                        status="violation",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.82,
                        message=f"No session auth on protected endpoint {_endpoint_key(ep)}",
                    ))

    result.compute_status()
    return result


def collect_auth_mechanism_evidence(
    resolved: ResolvedStandard,
    static_results: dict[str, StaticAnalysisResult],
) -> CategoryEvidenceResult:
    """Collect auth mechanism evidence (jwt_bearer, session, api_key, etc.).

    Uses AST-based dependency classification and middleware analysis to
    determine the actual authentication mechanism regardless of naming.
    """
    style = resolved.fastapi.get_style("auth_mechanism")
    markers = resolved.fastapi.get_markers("auth_mechanism")
    result = CategoryEvidenceResult(
        category="auth_mechanism",
        declared_style=style,
        overall_status="compliant",
    )

    if not style or style == "none":
        result.overall_status = "not_applicable"
        result.summary = "Auth mechanism is declared as not applicable."
        return result

    for repo_name, static in static_results.items():
        # 1. Check middleware-level mechanism
        mw_analysis = static.fastapi_facts.auth_middleware_analysis
        mw_covers = mw_analysis and mw_analysis.mechanism == style

        for ep in static.backend_endpoints:
            if _is_public_path(ep.path):
                continue
            if ep.route_intent in ("public_meta", "auth_entry"):
                continue
            if ep.is_websocket:
                if mw_analysis and mw_analysis.websocket_excluded:
                    continue

            # Check 1: Middleware covers this endpoint globally
            if mw_covers:
                # Verify endpoint is not excluded by middleware's public paths
                excluded = False
                if mw_analysis and mw_analysis.public_paths:
                    ep_path_lower = ep.path.lower()
                    for pub in mw_analysis.public_paths:
                        if pub.lower() in ep_path_lower:
                            excluded = True
                            break
                if not excluded:
                    result.add(Evidence(
                        category="auth_mechanism",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.92,
                        message=f"Middleware {style} covers {_endpoint_key(ep)}",
                        details={"mechanism_source": "middleware"},
                    ))
                    continue

            # Check 2: Per-endpoint dep_classifications
            if ep.auth_mechanism_detected == style:
                result.add(Evidence(
                    category="auth_mechanism",
                    style=style,
                    status="compliant",
                    file=ep.file,
                    line=ep.line,
                    endpoint=_endpoint_key(ep),
                    service=repo_name,
                    confidence=0.93,
                    message=f"Dependency chain uses {style} on {_endpoint_key(ep)}",
                    details={"mechanism_source": "dependency", "classifications": ep.dep_classifications},
                ))
                continue

            # Check 3: Any auth classification in dep_classifications
            has_auth_dep = any(dc.startswith("auth") for dc in ep.dep_classifications)
            if has_auth_dep:
                result.add(Evidence(
                    category="auth_mechanism",
                    style=style,
                    status="compliant",
                    file=ep.file,
                    line=ep.line,
                    endpoint=_endpoint_key(ep),
                    service=repo_name,
                    confidence=0.85,
                    message=f"Auth dependency detected (mechanism inferred) on {_endpoint_key(ep)}",
                    details={"classifications": ep.dep_classifications},
                ))
                continue

            # Check 4: Fall back to marker search
            text_pool = ep.dependencies + ep.call_refs + ep.decorators + ep.string_refs
            if markers and _has_any_marker(text_pool, markers):
                result.add(Evidence(
                    category="auth_mechanism",
                    style=style,
                    status="compliant",
                    file=ep.file,
                    line=ep.line,
                    endpoint=_endpoint_key(ep),
                    service=repo_name,
                    confidence=0.80,
                    message=f"Marker-based {style} detection on {_endpoint_key(ep)}",
                ))
                continue

            # No coverage found
            result.add(Evidence(
                category="auth_mechanism",
                style=style,
                status="violation",
                file=ep.file,
                line=ep.line,
                endpoint=_endpoint_key(ep),
                service=repo_name,
                confidence=0.82,
                message=f"No {style} mechanism on protected endpoint {_endpoint_key(ep)}",
                details={"expected_mechanism": style, "deps": ep.dependencies},
            ))

    result.compute_status()
    return result


def collect_authz_evidence(
    resolved: ResolvedStandard,
    static_results: dict[str, StaticAnalysisResult],
) -> CategoryEvidenceResult:
    """Collect authorization evidence based on declared authorization model."""

    style = resolved.fastapi.get_style("authz_model")
    markers = resolved.authz_markers + resolved.authz_enforcement_markers
    result = CategoryEvidenceResult(
        category="authz_model",
        declared_style=style,
        overall_status="compliant",
    )

    if style == "none":
        result.overall_status = "not_applicable"
        result.summary = "Authorization is declared as not applicable."
        return result

    mutating_methods = {"POST", "PUT", "PATCH", "DELETE"}

    for repo_name, static in static_results.items():
        enforcement_strategy = resolved.authz_enforcement_strategy

        if enforcement_strategy in ("middleware_authz_enforcement",):
            middleware_found = _has_any_marker(
                static.fastapi_facts.middleware_refs,
                resolved.authz_enforcement_markers,
            )
            if middleware_found:
                for ep in static.backend_endpoints:
                    if ep.method.upper() not in mutating_methods:
                        continue
                    if _is_public_path(ep.path):
                        continue
                    result.add(Evidence(
                        category="authz_model",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.90,
                        message=f"Authorization middleware covers {_endpoint_key(ep)}",
                    ))
            else:
                result.add(Evidence(
                    category="authz_model",
                    style=style,
                    status="violation",
                    service=repo_name,
                    confidence=0.85,
                    message="Declared authorization middleware but none found.",
                ))
        else:
            for ep in static.backend_endpoints:
                if ep.method.upper() not in mutating_methods:
                    continue
                if _is_public_path(ep.path):
                    continue
                if ep.route_intent in ("public_meta", "auth_entry"):
                    continue

                # Service-token-authenticated endpoints (internal microservices)
                if any(
                    "service_token" in dc for dc in ep.dep_classifications
                ):
                    result.add(Evidence(
                        category="authz_model",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.90,
                        message=f"Internal service endpoint — service-token auth, RBAC not applicable",
                    ))
                    continue

                # Self-service endpoints don't require RBAC
                if _is_self_service_path(ep.path):
                    result.add(Evidence(
                        category="authz_model",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.88,
                        message=f"Self-service endpoint — RBAC not required",
                    ))
                    continue

                text_pool = ep.dependencies + ep.call_refs + ep.decorators + ep.string_refs

                # Also check AST-based authz classifications
                has_semantic_authz = any(
                    dc.startswith("authz") for dc in ep.dep_classifications
                )

                if _has_any_marker(text_pool, markers) or has_semantic_authz:
                    result.add(Evidence(
                        category="authz_model",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.88,
                        message=f"Authorization check found on {_endpoint_key(ep)}",
                    ))
                else:
                    result.add(Evidence(
                        category="authz_model",
                        style=style,
                        status="violation",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.82,
                        message=f"No authorization check on mutating endpoint {_endpoint_key(ep)}",
                    ))

    result.compute_status()
    return result


def collect_ownership_evidence(
    resolved: ResolvedStandard,
    static_results: dict[str, StaticAnalysisResult],
) -> CategoryEvidenceResult:
    """Collect ownership/IDOR protection evidence."""

    style = resolved.fastapi.get_style("ownership_protection")
    markers = resolved.ownership_markers
    result = CategoryEvidenceResult(
        category="ownership_protection",
        declared_style=style,
        overall_status="compliant",
    )

    if style == "none":
        result.overall_status = "not_applicable"
        return result

    for repo_name, static in static_results.items():
        for ep in static.backend_endpoints:
            if "{" not in ep.path:
                continue
            if _is_public_path(ep.path):
                continue
            if ep.route_intent in ("public_meta", "auth_entry"):
                continue

            # Admin-only endpoints on global config resources don't need tenant scoping
            if _is_admin_only_endpoint(ep) and _is_global_resource_path(ep.path):
                result.add(Evidence(
                    category="ownership_protection",
                    style=style,
                    status="compliant",
                    file=ep.file,
                    line=ep.line,
                    endpoint=_endpoint_key(ep),
                    service=repo_name,
                    confidence=0.90,
                    message=f"Admin-only endpoint on global resource — ownership N/A",
                ))
                continue

            text_pool = ep.call_refs + ep.string_refs + ep.dependencies
            if _has_any_marker(text_pool, markers):
                result.add(Evidence(
                    category="ownership_protection",
                    style=style,
                    status="compliant",
                    file=ep.file,
                    line=ep.line,
                    endpoint=_endpoint_key(ep),
                    service=repo_name,
                    confidence=0.87,
                    message=f"Ownership check found on {_endpoint_key(ep)}",
                ))
            else:
                signals = ep.service_call_signals
                if signals.has_identity_comparison and signals.has_authorization_raise:
                    result.add(Evidence(
                        category="ownership_protection",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.88,
                        message=f"Service-layer ownership: compares {signals.identity_attrs_compared}",
                        details={"identity_attrs": signals.identity_attrs_compared},
                    ))
                elif signals.has_identity_comparison or signals.has_identity_filter:
                    result.add(Evidence(
                        category="ownership_protection",
                        style=style,
                        status="compliant",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.82,
                        message=f"Service-layer identity reference detected",
                        details={"identity_attrs": signals.identity_attrs_compared},
                    ))
                else:
                    result.add(Evidence(
                        category="ownership_protection",
                        style=style,
                        status="violation",
                        file=ep.file,
                        line=ep.line,
                        endpoint=_endpoint_key(ep),
                        service=repo_name,
                        confidence=0.83,
                        message=f"No ownership check on resource endpoint {_endpoint_key(ep)}",
                        details={"expected_markers": markers},
                    ))

    result.compute_status()
    return result


def _is_admin_only_endpoint(ep: BackendEndpoint) -> bool:
    """Check if endpoint is guarded by admin-role enforcement."""
    # Check AST-based dep classifications
    for dc in ep.dep_classifications:
        if "authz" in dc and any(
            role in dc.lower() for role in ("admin", "superuser", "staff")
        ):
            return True

    # Fall back to dependency name heuristics
    joined = " ".join(ep.dependencies + ep.call_refs + ep.decorators).lower()
    admin_patterns = (
        "require_role", "role_required", "admin_required",
        "is_admin", "is_superuser", "admin_only",
    )
    if any(p in joined for p in admin_patterns):
        role_args = " ".join(ep.string_refs).lower()
        if any(r in role_args for r in ("admin", "superuser", "staff")):
            return True

    return False


def _is_global_resource_path(path: str) -> bool:
    """Check if the path represents a global/system resource that doesn't need tenant scoping."""
    from src.standards.marker_registry import MarkerRegistry
    return MarkerRegistry.is_admin_resource_path(path) or MarkerRegistry.is_global_resource_path(path)


def _is_self_service_path(path: str) -> bool:
    """Check if the path is a self-service endpoint (e.g., /me/, /my/, /profile)."""
    from src.standards.marker_registry import MarkerRegistry
    return MarkerRegistry.is_self_service_path(path)
