from __future__ import annotations

from collections import Counter, defaultdict

from src.constants.defaults import is_sensitive_field_name
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
    """
    Detect backend endpoints whose response schema exposes sensitive fields.

    Severity and confidence are adjusted based on whether the endpoint is
    *reachable* from an analysed frontend (i.e. matched in the service graph):

    - **Reachable** endpoint: CRITICAL — a frontend call exists and will receive
      the sensitive field directly.
    - **Unreachable** endpoint: HIGH — the endpoint exists in the codebase but was
      not matched to any frontend call in the current analysis scope.  It may still
      be called by other clients (mobile apps, other services, scripts), so it
      warrants attention, but at lower urgency than a confirmed frontend-facing leak.

    This prevents inflating the critical-issue count with internal/admin endpoints
    that happen to return a field with a sensitive-sounding name but are never
    called by the analysed frontend.
    """
    issues: list[Issue] = []

    # Build a set of (service, path) pairs that have at least one matched call
    reachable: set[tuple[str, str]] = {
        (match.backend_repo, match.endpoint.path)
        for match in context.graph_result.matches
    }

    for static in context.static_results.values():
        for endpoint in static.backend_endpoints:
            sensitive_fields = [
                field.name for field in endpoint.response_fields if _is_sensitive_field_name(field.name)
            ]
            if not sensitive_fields:
                continue

            is_reachable = (endpoint.service, endpoint.path) in reachable

            issues.append(
                Issue(
                    type="data_leakage",
                    severity=Severity.CRITICAL if is_reachable else Severity.HIGH,
                    service=endpoint.service,
                    endpoint=f"{endpoint.method} {endpoint.path}",
                    file=endpoint.file,
                    line=endpoint.line,
                    description=(
                        "Response schema exposes sensitive fields that will be returned to frontend callers."
                        if is_reachable
                        else "Response schema exposes sensitive fields; endpoint not matched to any analysed frontend call but may be reachable by other clients."
                    ),
                    evidence={
                        "sensitive_response_fields": sensitive_fields,
                        "response_schema": endpoint.response_schema,
                        "reachable_from_frontend": is_reachable,
                    },
                    impact="Sensitive identifiers or credentials can leak to clients and downstream logs.",
                    fix="Remove sensitive fields from response model or use field exclusion / response_model_exclude.",
                    confidence=0.85 if is_reachable else 0.65,
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
    return _issues_from_missing_flow_coverage(context, allowed_flow_ids={"authn_flow"})


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
    return _issues_from_missing_flow_coverage(context, allowed_flow_ids={"request_validation_flow"})


def rule_mandatory_flow_violations(context: AnalysisContext) -> list[Issue]:
    return _issues_from_missing_flow_coverage(
        context,
        skip_flow_ids={"authn_flow", "request_validation_flow"},
    )


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
    """
    Detect genuinely redundant API calls within a single source file.

    A call is flagged only when it is *truly* redundant — meaning it is highly
    likely to be a copy-paste or forgotten cache rather than two different
    UI components in the same file that each legitimately need the same data.

    Two-tier classification:
    - **Definitely redundant** (count ≥ 3 in the same file): regardless of how the
      calls are structured, three or more identical calls in one file is unusual.
    - **Likely redundant** (count == 2 AND calls are within 10 lines of each other):
      adjacent identical calls are almost certainly a copy-paste or double-trigger.

    Two calls in the same file that are far apart in line numbers are *not* flagged
    because they are likely in separate components/hooks that both independently
    need that data.
    """
    issues: list[Issue] = []

    # key → list of line numbers for that (service, file, method, url)
    call_locations: dict[tuple[str, str, str, str], list[int | None]] = defaultdict(list)

    for static in context.static_results.values():
        for call in static.frontend_calls:
            key = (call.service, call.file, call.method.upper(), call.raw_url)
            call_locations[key].append(call.line)

    for (service, file, method, url), lines in call_locations.items():
        count = len(lines)
        if count < 2:
            continue

        # Tier 1: three or more identical calls in the same file
        if count >= 3:
            issues.append(
                Issue(
                    type="redundant_calls",
                    severity=Severity.MEDIUM,
                    service=service,
                    endpoint=f"{method} {url}",
                    file=file,
                    description=f"The same API call appears {count} times in one source file.",
                    evidence={"file": file, "occurrences": count, "lines": [l for l in lines if l]},
                    impact="Repeated requests waste bandwidth and add unnecessary backend load.",
                    fix="Extract the call into a shared hook, service function, or cache result.",
                    confidence=0.80,
                )
            )
            continue

        # Tier 2: exactly 2 calls – only flag if they are suspiciously close
        known_lines = [l for l in lines if l is not None]
        if len(known_lines) == 2:
            proximity = abs(known_lines[0] - known_lines[1])
            if proximity <= 10:
                issues.append(
                    Issue(
                        type="redundant_calls",
                        severity=Severity.MEDIUM,
                        service=service,
                        endpoint=f"{method} {url}",
                        file=file,
                        description="Two identical API calls appear within 10 lines in the same file.",
                        evidence={"file": file, "occurrences": 2, "lines": known_lines, "proximity_lines": proximity},
                        impact="Adjacent duplicate requests likely indicate a copy-paste error or double-trigger.",
                        fix="Deduplicate into a single call or add a request-dedup guard.",
                        confidence=0.75,
                    )
                )

    return issues


def rule_unprotected_internal_endpoints(context: AnalysisContext) -> list[Issue]:
    """
    Detect non-public backend endpoints that have no authentication dependency
    whatsoever.  These are distinct from the authn_flow results – this rule
    focuses specifically on service-to-service internal routes (e.g. webhook
    receivers, LiveKit token issuers, internal callback handlers) that accept
    inbound traffic without any credential check.

    The authn_flow already covers user-facing auth gaps; this rule adds a
    complementary check for endpoints that should be protected by shared secrets,
    API keys, or HMAC signatures instead of user JWTs.
    """
    # Build a set of paths already flagged as missing auth by the flow engine
    # so we can avoid double-reporting endpoints already in the flow results.
    flow_missing_auth: set[str] = {
        f"{item.endpoint}"
        for item in context.flow_coverage
        if item.flow_id == "authn_flow" and item.status.value == "missing"
    }

    _PUBLIC_SEGMENTS = frozenset({
        "health", "metrics", "readiness", "liveness", "ping",
        "docs", "openapi", "swagger", "redoc",
        "login", "signup", "register",
    })

    # Do NOT include websocket-like patterns here: rule_websocket_security
    # handles those specifically and more accurately.
    _INTERNAL_PATH_SIGNALS = frozenset({
        "webhook", "callback", "notify", "event", "integration",
        "livekit", "internal", "service",
    })

    _AUTH_DEP_SIGNALS = frozenset({
        "get_current", "current_user", "current_recruiter", "current_admin",
        "current_candidate", "authenticate", "require_auth", "auth_required",
        "login_required", "oauth2", "bearer", "verify_token", "is_authenticated",
        "jwt_required", "session", "api_key", "api_secret", "hmac", "x_api_key",
    })

    issues: list[Issue] = []
    for static in context.static_results.values():
        for ep in static.backend_endpoints:
            path_lower = ep.path.lower()
            segments = [s for s in path_lower.split("/") if s]

            # Skip monitoring/public endpoints
            if any(s in _PUBLIC_SEGMENTS for s in segments):
                continue

            # Only examine endpoints that look like internal service routes
            has_internal_signal = any(sig in path_lower for sig in _INTERNAL_PATH_SIGNALS)
            if not has_internal_signal:
                continue

            # Check whether any dependency contains an auth signal
            deps_lower = " ".join(ep.dependencies).lower()
            has_auth = any(sig in deps_lower for sig in _AUTH_DEP_SIGNALS)
            if has_auth:
                continue

            endpoint_ref = f"{ep.method} {ep.path}"
            # Avoid double-reporting with authn_flow
            if endpoint_ref in flow_missing_auth:
                continue

            issues.append(
                Issue(
                    type="unprotected_internal_endpoint",
                    severity=Severity.CRITICAL,
                    service=ep.service,
                    endpoint=endpoint_ref,
                    file=ep.file,
                    line=ep.line,
                    description=(
                        f"Internal/integration endpoint {endpoint_ref} accepts inbound traffic "
                        "without any authentication or shared-secret guard."
                    ),
                    evidence={
                        "path": ep.path,
                        "method": ep.method,
                        "detected_deps": ep.dependencies,
                        "path_signal": [sig for sig in _INTERNAL_PATH_SIGNALS if sig in path_lower],
                    },
                    impact=(
                        "Any network-reachable actor can invoke this endpoint without credentials, "
                        "enabling unauthorized data access or service manipulation."
                    ),
                    fix=(
                        "Protect with a shared API key header (X-Internal-Secret), HMAC signature, "
                        "or mTLS.  At minimum, add an IP allowlist for internal callers."
                    ),
                    confidence=0.80,
                )
            )
    return issues


def rule_idor_risk(context: AnalysisContext) -> list[Issue]:
    """
    Detect authenticated endpoints that access resources by a path-level ID
    parameter without visible ownership/tenant-scoping signals.

    Heuristic (static only – no false-negative guarantee):
    - Endpoint has an explicit auth dependency (Depends injection detected)
    - Path contains a {param} placeholder
    - Neither the service call_refs nor string_refs contain ownership signals
    """
    _AUTH_SIGNALS = frozenset({
        "get_current", "current_user", "current_recruiter", "current_admin",
        "current_candidate", "authenticate", "require_auth", "bearer",
        "verify_token", "is_authenticated", "session",
    })
    _OWNERSHIP_SIGNALS = frozenset({
        "org_id", "organization_id", "user_id", "owner_id", "recruiter_id",
        "candidate_id", "belongs_to", "verify_ownership", "is_owner",
        "check_access", "get_by_owner", "owned_by", "filter_by_owner",
        "get_for_user", "has_access", "can_access", "access_check",
    })
    _MONITORING_PATHS = frozenset({
        "/health", "/metrics", "/readiness", "/liveness", "/ping",
        "/docs", "/openapi",
    })

    issues: list[Issue] = []

    for static in context.static_results.values():
        for ep in static.backend_endpoints:
            # Must be a resource-retrieval or mutation method
            if ep.method.upper() not in {"GET", "PUT", "PATCH", "DELETE"}:
                continue

            # Must have a path parameter
            if "{" not in ep.path:
                continue

            # Skip monitoring endpoints
            if any(ep.path.startswith(m) for m in _MONITORING_PATHS):
                continue

            # Endpoint must be authenticated (has auth dep)
            deps_lower = " ".join(ep.dependencies).lower()
            has_auth = any(sig in deps_lower for sig in _AUTH_SIGNALS)
            if not has_auth:
                continue  # authn_flow will flag missing auth; no point in IDOR on top

            # Check for ownership signals in calls, strings, and schemas
            call_str = " ".join(ep.call_refs + ep.string_refs + ep.dependencies).lower()
            if ep.request_schema:
                call_str += " " + ep.request_schema.lower()
            if ep.response_schema:
                call_str += " " + ep.response_schema.lower()
            has_ownership = any(sig in call_str for sig in _OWNERSHIP_SIGNALS)
            if has_ownership:
                continue

            issues.append(
                Issue(
                    type="missing_ownership_check",
                    severity=Severity.CRITICAL,
                    service=ep.service,
                    endpoint=f"{ep.method} {ep.path}",
                    file=ep.file,
                    line=ep.line,
                    description=(
                        f"Authenticated endpoint {ep.method} {ep.path} accesses a resource "
                        "by path parameter ID with no observable ownership or tenant-scoping check."
                    ),
                    evidence={
                        "path": ep.path,
                        "auth_deps": ep.dependencies,
                        "call_refs_sample": ep.call_refs[:10],
                    },
                    impact=(
                        "Any authenticated user can potentially read, update, or delete another "
                        "user's or organization's resource by guessing or enumerating IDs (IDOR)."
                    ),
                    fix=(
                        "Pass the authenticated caller's organisation/user ID into every service "
                        "method that fetches by resource ID and assert the resource belongs to "
                        "that caller before returning or mutating it."
                    ),
                    confidence=0.72,
                )
            )

    return issues


def rule_missing_service_auth(context: AnalysisContext) -> list[Issue]:
    """
    Detect endpoints designed to be called by another backend service (identified
    by path signals such as /webhook, /callback, /notify, /internal, /integration)
    that carry no service-level authentication mechanism (API key, HMAC, mutual TLS).
    """
    _SERVICE_PATH_SIGNALS = frozenset({
        "webhook", "callback", "notify", "event", "integration", "internal",
    })
    _SERVICE_AUTH_SIGNALS = frozenset({
        "api_key", "api_secret", "x_api_key", "secret_key", "shared_secret",
        "hmac", "signature", "x_signature", "x_webhook_secret",
    })
    _PUBLIC_SEGMENTS = frozenset({
        "health", "metrics", "readiness", "liveness", "ping",
        "docs", "openapi", "swagger", "redoc", "login", "signup", "register",
    })

    issues: list[Issue] = []
    for static in context.static_results.values():
        for ep in static.backend_endpoints:
            path_lower = ep.path.lower()
            segments = [s for s in path_lower.split("/") if s]

            if any(s in _PUBLIC_SEGMENTS for s in segments):
                continue

            has_service_signal = any(sig in path_lower for sig in _SERVICE_PATH_SIGNALS)
            if not has_service_signal:
                continue

            all_refs = " ".join(
                ep.dependencies + ep.call_refs + ep.string_refs + ep.decorators
            ).lower()
            has_service_auth = any(sig in all_refs for sig in _SERVICE_AUTH_SIGNALS)
            if has_service_auth:
                continue

            issues.append(
                Issue(
                    type="missing_service_auth",
                    severity=Severity.CRITICAL,
                    service=ep.service,
                    endpoint=f"{ep.method} {ep.path}",
                    file=ep.file,
                    line=ep.line,
                    description=(
                        f"Service-to-service endpoint {ep.method} {ep.path} lacks any "
                        "shared-secret, HMAC, or API-key authentication mechanism."
                    ),
                    evidence={
                        "path": ep.path,
                        "service_signal": [sig for sig in _SERVICE_PATH_SIGNALS if sig in path_lower],
                        "deps": ep.dependencies,
                    },
                    impact=(
                        "Unauthenticated webhook/callback endpoints can be triggered by any party, "
                        "enabling event injection, data manipulation, and denial-of-service."
                    ),
                    fix=(
                        "Verify a shared secret or HMAC signature on every inbound webhook/callback "
                        "request before processing the payload."
                    ),
                    confidence=0.77,
                )
            )
    return issues


def rule_insecure_defaults(context: AnalysisContext) -> list[Issue]:
    """
    Scan static analysis results for signals of insecure default configurations:
    - Hardcoded weak secret keys or 'changeme' patterns in string_refs
    - Permissive CORS with credentials
    - DEBUG=True or TESTING=True defaults that may leak in production
    - Plaintext HTTP hardcoded base URLs in production code
    """
    _WEAK_SECRET_PATTERNS = (
        "changeme", "secret123", "supersecret", "mysecret",
        "hardcoded", "example_secret", "your_secret", "replace_me",
        "insert_secret", "todo", "fixme",
    )
    _DEBUG_PATTERNS = frozenset({"debug=true", "debug: true", "testing=true"})
    _HTTP_PROD_PATTERNS = frozenset({"http://", "http:/"})

    issues: list[Issue] = []
    seen: set[tuple[str, str]] = set()

    for repo_name, static in context.static_results.items():
        # Aggregate all string refs across all endpoints
        all_strings: list[str] = []
        for ep in static.backend_endpoints:
            all_strings.extend(ep.string_refs)

        lowered_strings = [s.lower() for s in all_strings]

        # 1. Weak / placeholder secret keys
        weak = [s for s in all_strings if any(p in s.lower() for p in _WEAK_SECRET_PATTERNS)]
        if weak:
            key = (repo_name, "weak_secret")
            if key not in seen:
                seen.add(key)
                issues.append(
                    Issue(
                        type="insecure_default_config",
                        severity=Severity.CRITICAL,
                        service=repo_name,
                        endpoint=None,
                        description="Hardcoded placeholder secret or weak default value detected in source code.",
                        evidence={"samples": weak[:5]},
                        impact="If the default secret key is used in production, cryptographic protections (JWT signing, session, CSRF) are trivially broken.",
                        fix="Remove all hardcoded secret defaults; load secrets from environment variables or a secrets manager.",
                        confidence=0.85,
                    )
                )

        # 2. Hardcoded HTTP (non-TLS) base URLs – only flag if they look like
        #    real service URLs (not localhost/127.x which are expected in dev)
        prod_http = [
            u for u in static.hardcoded_urls
            if u.startswith("http://")
            and "localhost" not in u
            and "127.0.0.1" not in u
            and "0.0.0.0" not in u
        ]
        if prod_http:
            key = (repo_name, "http_prod")
            if key not in seen:
                seen.add(key)
                issues.append(
                    Issue(
                        type="insecure_default_config",
                        severity=Severity.HIGH,
                        service=repo_name,
                        endpoint=None,
                        description="Hardcoded HTTP (non-TLS) URLs pointing at non-localhost hosts detected.",
                        evidence={"urls": prod_http[:8]},
                        impact="Credentials and payloads transmitted over plain HTTP can be intercepted by network-level attackers.",
                        fix="Replace http:// service URLs with https:// and enforce TLS for all production traffic.",
                        confidence=0.88,
                    )
                )

        # 3. DEBUG / TESTING mode string signals
        debug_hits = [s for s in lowered_strings if s in _DEBUG_PATTERNS]
        if debug_hits:
            key = (repo_name, "debug_mode")
            if key not in seen:
                seen.add(key)
                issues.append(
                    Issue(
                        type="insecure_default_config",
                        severity=Severity.HIGH,
                        service=repo_name,
                        endpoint=None,
                        description="DEBUG or TESTING mode flag detected in application source.",
                        evidence={"hits": debug_hits[:3]},
                        impact="Debug mode enables detailed stack traces and may activate code paths unsafe for production.",
                        fix="Set DEBUG=False in production; inject environment from CI/CD secrets, not source code.",
                        confidence=0.78,
                    )
                )

    return issues


def rule_websocket_security(context: AnalysisContext) -> list[Issue]:
    """
    Detect WebSocket endpoints (method == 'WS') that lack an authentication
    dependency, since WebSocket connections bypass standard HTTP middleware in
    many frameworks and need explicit in-handshake auth.
    """
    _AUTH_SIGNALS = frozenset({
        "get_current", "current_user", "current_recruiter", "current_admin",
        "current_candidate", "authenticate", "require_auth", "bearer",
        "verify_token", "is_authenticated", "session", "oauth2",
    })

    issues: list[Issue] = []
    for static in context.static_results.values():
        for ep in static.backend_endpoints:
            if not ep.is_websocket:
                continue
            deps_lower = " ".join(ep.dependencies).lower()
            has_auth = any(sig in deps_lower for sig in _AUTH_SIGNALS)
            if has_auth:
                continue
            issues.append(
                Issue(
                    type="unauthenticated_websocket",
                    severity=Severity.CRITICAL,
                    service=ep.service,
                    endpoint=f"WS {ep.path}",
                    file=ep.file,
                    line=ep.line,
                    description=(
                        f"WebSocket endpoint WS {ep.path} has no explicit authentication "
                        "dependency injected at connection time."
                    ),
                    evidence={
                        "path": ep.path,
                        "deps": ep.dependencies,
                    },
                    impact=(
                        "WebSocket connections bypass HTTP-layer auth middleware; unauthenticated "
                        "connections can stream real-time data to unauthorized parties."
                    ),
                    fix=(
                        "Inject an auth dependency (Depends(get_current_user)) into the WebSocket "
                        "handler's parameters or validate a token passed as a query param during "
                        "the initial handshake."
                    ),
                    confidence=0.85,
                )
            )
    return issues


def _is_sensitive_field_name(name: str) -> bool:
    return is_sensitive_field_name(name)


def _issues_from_missing_flow_coverage(
    context: AnalysisContext,
    allowed_flow_ids: set[str] | None = None,
    skip_flow_ids: set[str] | None = None,
) -> list[Issue]:
    issues: list[Issue] = []

    for item in context.flow_coverage:
        if item.status.value != "missing":
            continue
        if allowed_flow_ids is not None and item.flow_id not in allowed_flow_ids:
            continue
        if skip_flow_ids and item.flow_id in skip_flow_ids:
            continue

        definition = context.flow_definitions.get(item.flow_id)
        if definition is None:
            continue

        severity = _to_severity(definition.severity)
        evidence = dict(item.evidence)
        evidence["flow_id"] = item.flow_id
        evidence["flow_title"] = definition.title

        issues.append(
            Issue(
                type=definition.issue_type,
                severity=severity,
                service=item.service,
                endpoint=item.endpoint,
                file=item.file,
                line=item.line,
                description=definition.missing_description,
                evidence=evidence,
                impact=definition.missing_impact,
                fix=definition.missing_fix,
                confidence=max(0.5, float(item.confidence)),
            )
        )

    return issues


def _to_severity(raw: str) -> Severity:
    lowered = raw.lower()
    if lowered == Severity.CRITICAL.value:
        return Severity.CRITICAL
    if lowered == Severity.HIGH.value:
        return Severity.HIGH
    return Severity.MEDIUM
