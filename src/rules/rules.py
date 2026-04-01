from __future__ import annotations

from collections import Counter, defaultdict

from src.constants.defaults import PUBLIC_PATH_MARKERS, SENSITIVE_FIELD_MARKERS
from src.schemas.internal import AnalysisContext
from src.schemas.issues import Issue, Severity


def rule_contract_violations(context: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []
    for item in context.contract_issues:
        issues.append(
            Issue(
                type=item["type"],
                severity=Severity(item["severity"]),
                service=item["service"],
                endpoint=item.get("endpoint"),
                file=item.get("file"),
                line=item.get("line"),
                description=item["description"],
                evidence=item.get("evidence", {}),
                impact=item["impact"],
                fix=item["fix"],
                confidence=float(item.get("confidence", 0.8)),
            )
        )
    return issues


def rule_data_leakage(context: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []

    for static in context.static_results.values():
        for endpoint in static.backend_endpoints:
            sensitive_fields = [
                field.name for field in endpoint.response_fields if _is_sensitive_field_name(field.name)
            ]
            if not sensitive_fields:
                continue
            issues.append(
                Issue(
                    type="data_leakage",
                    severity=Severity.CRITICAL,
                    service=endpoint.service,
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    file=endpoint.file,
                    line=endpoint.line,
                    description="Response schema exposes sensitive fields in API output.",
                    evidence={"sensitive_response_fields": sensitive_fields, "response_schema": endpoint.response_schema},
                    impact="Sensitive identifiers or credentials can leak to clients and downstream logs.",
                    fix="Remove sensitive fields from response model or mask them before serialization.",
                    confidence=0.85,
                )
            )

    return issues


def rule_broken_service_connection(context: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []

    for unmatched in context.graph_result.unmatched_calls:
        issues.append(
            Issue(
                type="broken_service_connection",
                severity=Severity.CRITICAL,
                service=unmatched.service,
                endpoint=f"{unmatched.method} {unmatched.raw_url}",
                file=unmatched.file,
                line=unmatched.line,
                description="Frontend API call could not be mapped to any backend route.",
                evidence={
                    "raw_url": unmatched.raw_url,
                    "resolved_url": unmatched.resolved_url,
                    "method": unmatched.method,
                    "file": unmatched.file,
                },
                impact="Calls are likely to fail at runtime with network or 404 errors.",
                fix="Align frontend base URL/path with existing backend endpoints or implement missing endpoint.",
                confidence=0.88,
            )
        )

    runtime = context.runtime_result
    if runtime:
        for service, state in runtime.service_status.items():
            lowered = state.lower()
            if any(marker in lowered for marker in ["exited", "dead", "unhealthy", "error"]):
                issues.append(
                    Issue(
                        type="broken_service_connection",
                        severity=Severity.CRITICAL,
                        service=service,
                        endpoint=None,
                        description="Service failed during runtime integration execution.",
                        evidence={"state": state},
                        impact="Downstream calls to this service will fail in production.",
                        fix="Inspect container logs, startup command, and dependency connectivity.",
                        confidence=0.9,
                    )
                )

        for error in runtime.errors:
            issues.append(
                Issue(
                    type="runtime_failure",
                    severity=Severity.CRITICAL,
                    service="runtime",
                    endpoint=None,
                    description="Runtime orchestration failed for one or more services.",
                    evidence={"error": error},
                    impact="Integration and traffic validation cannot be trusted until runtime succeeds.",
                    fix="Resolve build/startup errors and re-run runtime validation.",
                    confidence=0.92,
                )
            )

    return issues


def rule_missing_auth(context: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []
    protected_methods = {"POST", "PUT", "PATCH", "DELETE"}

    for static in context.static_results.values():
        for endpoint in static.backend_endpoints:
            if endpoint.method.upper() not in protected_methods:
                continue
            if endpoint.path in PUBLIC_PATH_MARKERS:
                continue
            if any(endpoint.path.startswith(marker) for marker in PUBLIC_PATH_MARKERS):
                continue
            if _contains_auth_dependency(endpoint.dependencies):
                continue

            issues.append(
                Issue(
                    type="missing_auth",
                    severity=Severity.CRITICAL,
                    service=endpoint.service,
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    file=endpoint.file,
                    line=endpoint.line,
                    description="Mutable endpoint is missing explicit auth/identity dependency.",
                    evidence={"dependencies": endpoint.dependencies, "file": endpoint.file},
                    impact="Unauthorized callers may execute privileged operations.",
                    fix="Attach authentication/authorization dependency (e.g. JWT/session guard).",
                    confidence=0.84,
                )
            )

    return issues


def rule_partial_mismatch(context: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []
    mismatch_by_service: dict[str, list[dict]] = defaultdict(list)

    for item in context.contract_issues:
        if item.get("type") in {"type_mismatch", "missing_fields", "extra_fields"}:
            mismatch_by_service[item["service"]].append(item)

    for service, service_mismatches in mismatch_by_service.items():
        if len(service_mismatches) < 2:
            continue
        issues.append(
            Issue(
                type="partial_mismatch",
                severity=Severity.HIGH,
                service=service,
                endpoint=None,
                description="Multiple partial request/contract mismatches detected across integration points.",
                evidence={"mismatch_count": len(service_mismatches)},
                impact="Feature behavior may be inconsistent across flows despite partial success.",
                fix="Standardize DTO contracts and regenerate shared API types/clients.",
                confidence=0.79,
            )
        )

    return issues


def rule_missing_validation(context: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []

    for static in context.static_results.values():
        for endpoint in static.backend_endpoints:
            if endpoint.method.upper() not in {"POST", "PUT", "PATCH"}:
                continue
            if endpoint.request_schema:
                continue
            issues.append(
                Issue(
                    type="missing_validation",
                    severity=Severity.HIGH,
                    service=endpoint.service,
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    file=endpoint.file,
                    line=endpoint.line,
                    description="Write endpoint has no explicit request schema validation.",
                    evidence={"request_schema": endpoint.request_schema, "file": endpoint.file},
                    impact="Malformed payloads can pass unchecked and corrupt downstream state.",
                    fix="Introduce strict Pydantic request models and validation constraints.",
                    confidence=0.81,
                )
            )

    return issues


def rule_hardcoded_configs(context: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []

    for repo_name, static in context.static_results.items():
        hardcoded = static.hardcoded_urls
        if not hardcoded:
            continue

        risky = [url for url in hardcoded if "localhost" in url or "127.0.0.1" in url or "http://" in url]
        if not risky:
            continue

        severity = Severity.HIGH if len(risky) >= 2 else Severity.MEDIUM
        issues.append(
            Issue(
                type="hardcoded_config",
                severity=severity,
                service=repo_name,
                endpoint=None,
                description="Hardcoded service URLs detected; configuration is not environment-safe.",
                evidence={"urls": risky[:15]},
                impact="Deployments across environments may break due to fixed host/port assumptions.",
                fix="Externalize URLs into inferred env variables and inject at runtime.",
                confidence=0.82,
            )
        )

    return issues


def rule_over_fetching(context: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []
    for match in context.graph_result.matches:
        if match.call.method.upper() != "GET":
            continue
        response_field_count = len(match.endpoint.response_fields)
        if response_field_count < 12:
            continue
        issues.append(
            Issue(
                type="over_fetching",
                severity=Severity.MEDIUM,
                service=match.frontend_repo,
                endpoint=f"GET {match.endpoint.path}",
                file=match.call.file,
                line=match.call.line,
                description="Frontend likely over-fetches data from large response contract.",
                evidence={"response_field_count": response_field_count},
                impact="Unnecessary payload transfer increases latency and client processing cost.",
                fix="Introduce lean response DTOs or selective field/query projection.",
                confidence=0.68,
            )
        )
    return issues


def rule_redundant_calls(context: AnalysisContext) -> list[Issue]:
    issues: list[Issue] = []
    counter: Counter[tuple[str, str, str, str]] = Counter()

    for static in context.static_results.values():
        for call in static.frontend_calls:
            key = (call.service, call.file, call.method.upper(), call.raw_url)
            counter[key] += 1

    for (service, file, method, url), count in counter.items():
        if count < 2:
            continue
        issues.append(
            Issue(
                type="redundant_calls",
                severity=Severity.MEDIUM,
                service=service,
                endpoint=f"{method} {url}",
                file=file,
                description="Duplicate frontend API calls detected in same source file.",
                evidence={"file": file, "occurrences": count},
                impact="Repeated requests can waste bandwidth and cause unnecessary backend load.",
                fix="Deduplicate repeated request triggers or cache call results.",
                confidence=0.72,
            )
        )

    return issues


def _contains_auth_dependency(dependencies: list[str]) -> bool:
    markers = {"auth", "jwt", "token", "user", "session", "permission", "scope", "oauth"}
    for dependency in dependencies:
        lowered = dependency.lower()
        if any(marker in lowered for marker in markers):
            return True
    return False


def _is_sensitive_field_name(name: str) -> bool:
    lowered = name.lower()
    return any(marker in lowered for marker in SENSITIVE_FIELD_MARKERS)
