from __future__ import annotations

import re
from urllib.parse import urlparse

from src.schemas.internal import BackendEndpoint, FastAPIGlobalFacts, FrontendCall, StaticAnalysisResult

_PUBLIC_META_EXACT = {
    "/",
    "/docs",
    "/redoc",
    "/openapi",
    "/openapi.json",
    "/metrics",
    "/health",
    "/healthz",
    "/status",
    "/statusz",
    "/readiness",
    "/liveness",
    "/ping",
}
_PUBLIC_META_SEGMENTS = {
    "docs",
    "redoc",
    "openapi",
    "metrics",
    "health",
    "healthz",
    "status",
    "statusz",
    "readiness",
    "liveness",
    "ping",
}
_AUTH_ENTRY_MARKERS = (
    "/auth",
    "/login",
    "/signup",
    "/register",
    "/token",
    "/forgot",
    "/password/reset",
    "/password/forgot",
    "/password/verify",
    "/verify",
    "/otp",
    "/invite/accept",
)
_WEBHOOK_MARKERS = frozenset({"webhook", "notify", "event"})
_INTERNAL_CALLBACK_MARKERS = frozenset({"callback", "internal", "integration"})
_SERVICE_PATH_MARKERS = _WEBHOOK_MARKERS | _INTERNAL_CALLBACK_MARKERS | frozenset({"service"})

_SERVICE_AUTH_MARKERS = frozenset({
    "service_token",
    "require_service_token",
    "x-service-token",
    "x_service_token",
    "api_key",
    "x-api-key",
    "x_api_key",
    "shared_secret",
    "hmac",
    "signature",
    "webhook_secret",
})
_USER_AUTH_MARKERS = frozenset({
    "get_current",
    "current_user",
    "current_admin",
    "current_staff",
    "current_member",
    "current_teacher",
    "current_student",
    "current_manager",
    "current_operator",
    "authenticated_user",
    "verified_user",
    "authenticate",
    "require_auth",
    "auth_required",
    "login_required",
    "oauth2",
    "bearer",
    "verify_token",
    "jwt_required",
    "session",
    "security(",
    "security",
})
_AUTH_AMBIGUOUS_MARKERS = frozenset({"user", "identity", "principal", "actor"})
_AUTH_MIDDLEWARE_KEYWORDS = frozenset({"jwt", "auth", "bearer", "token", "session", "oauth"})

_OWNERSHIP_COVERED_PATTERNS: tuple[re.Pattern[str], ...] = (
    re.compile(r"\bensure_[a-z0-9_]*(?:enrollment|ownership|access|scope)\b"),
    re.compile(r"\bensure_[a-z0-9_]*can_access\b"),
    re.compile(r"\bget_[a-z0-9_]*_for_user\b"),
    re.compile(r"\b_get_[a-z0-9_]*_for_user\b"),
    re.compile(r"\bfilter_[a-z0-9_]*owner\b"),
    re.compile(r"\bfilter_[a-z0-9_]*tenant\b"),
    re.compile(r"\bscoped_[a-z0-9_]*query\b"),
    re.compile(r"\bwhere\s+.*user_id\b"),
)
_OWNERSHIP_MARKERS = frozenset({
    "org_id",
    "organization_id",
    "user_id",
    "owner_id",
    "tenant_id",
    "belongs_to",
    "verify_ownership",
    "is_owner",
    "check_access",
    "check_scope",
    "ensure_enrollment",
    "ensure_student_enrollment",
    "ensure_access",
    "ensure_student_can_access_concept",
    "get_for_user",
    "get_by_user",
    "filter_by_owner",
    "owned_by",
    "scoped_to",
    "current_user",
})
_OWNERSHIP_AMBIGUOUS_MARKERS = frozenset({"permission", "can_access", "has_access", "access_check"})

_TRAILING_CONCAT_RE = re.compile(r"(?:\s*\+\s*[A-Za-z_$][\w.$]*)+$")
_PLACEHOLDER_SEGMENT_RE = re.compile(r"^\$?\{[^}]+\}$|^[A-Z][A-Z0-9_]*$|^:[A-Za-z_][\w]*$")


def normalize_static_results(static_results: dict[str, StaticAnalysisResult]) -> None:
    for static in static_results.values():
        for endpoint in static.backend_endpoints:
            refs = _combined_refs(endpoint, static.fastapi_facts)
            endpoint.canonical_path = canonicalize_path(endpoint.path)
            endpoint.route_intent = classify_route_intent(endpoint.path, endpoint.method, refs)
            endpoint.auth_mode = classify_auth_mode(endpoint, static.fastapi_facts)
            endpoint.ownership_mode = classify_ownership_mode(endpoint)
        for call in static.frontend_calls:
            call.payload_resolution = classify_payload_resolution(call)
            call.canonical_path = canonicalize_url_path(call.resolved_url or call.raw_url)
            call.canonical_url = canonicalize_url(call.resolved_url or call.raw_url)


def canonicalize_url(url: str) -> str:
    path = canonicalize_frontend_url_path(url)
    return path


def canonicalize_url_path(url_or_path: str) -> str:
    return canonicalize_frontend_url_path(url_or_path)


def canonicalize_frontend_url_path(url_or_path: str) -> str:
    raw = (url_or_path or "").strip().strip('"\'`')
    if not raw:
        return "/"
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        raw = parsed.path or "/"
    raw = raw.split("#", 1)[0]
    raw = raw.split("?", 1)[0]
    raw = _TRAILING_CONCAT_RE.sub("", raw).strip()
    if not raw.startswith("/"):
        raw = f"/{raw.lstrip('/')}"
    raw = re.sub(r"/{2,}", "/", raw)

    parts = [part for part in raw.split("/") if part]
    normalized_parts: list[str] = []
    for part in parts:
        if _PLACEHOLDER_SEGMENT_RE.match(part):
            normalized_parts.append("{param}")
            continue
        if "${" in part:
            normalized_parts.append("{param}")
            continue
        normalized_parts.append(part)

    parts = normalized_parts
    while parts and _PLACEHOLDER_SEGMENT_RE.match(parts[0]):
        parts.pop(0)
    normalized = "/" + "/".join(parts) if parts else "/"
    if len(normalized) > 1:
        normalized = normalized.rstrip("/") or "/"
    return normalized


def canonicalize_path(path: str) -> str:
    return canonicalize_backend_path(path)


def canonicalize_backend_path(path: str) -> str:
    raw = (path or "").strip().strip('"\'`')
    if not raw:
        return "/"
    if raw.startswith(("http://", "https://")):
        parsed = urlparse(raw)
        raw = parsed.path or "/"
    raw = raw.split("#", 1)[0]
    raw = raw.split("?", 1)[0]
    if not raw.startswith("/"):
        raw = f"/{raw.lstrip('/')}"
    raw = re.sub(r"/{2,}", "/", raw)
    if len(raw) > 1:
        raw = raw.rstrip("/") or "/"
    return raw


def classify_payload_resolution(call: FrontendCall) -> str:
    if call.payload_fields:
        return "resolved"
    if call.payload_unresolved:
        return "unresolved"
    return "none"


def classify_route_intent(path: str, method: str, refs: list[str] | None = None) -> str:
    canonical = canonicalize_path(path)
    refs = refs or []
    lower_text = " ".join(refs)
    if canonical in _PUBLIC_META_EXACT:
        return "public_meta"

    segments = [part for part in canonical.split("/") if part]
    if segments and all(part in _PUBLIC_META_SEGMENTS for part in segments):
        return "public_meta"

    if any(marker in canonical for marker in _AUTH_ENTRY_MARKERS):
        return "auth_entry"

    if any(marker in canonical for marker in ("/webhook", "/notify", "/event")):
        return "webhook"

    if any(marker in canonical for marker in ("/callback", "/internal", "/integration")):
        return "internal_callback"

    if any(marker in lower_text for marker in _SERVICE_AUTH_MARKERS) or any(
        token in canonical.lower() for token in _SERVICE_PATH_MARKERS
    ):
        return "service_endpoint"

    if canonical == "/" and method.upper() in {"GET", "HEAD"}:
        return "public_meta"

    return "business_endpoint"


def classify_auth_mode(endpoint: BackendEndpoint, facts: FastAPIGlobalFacts) -> str:
    refs = _combined_refs(endpoint, facts)
    route_intent = endpoint.route_intent or classify_route_intent(endpoint.path, endpoint.method, refs)
    if route_intent in {"public_meta", "auth_entry"}:
        return "public"

    if _match_markers(refs, _SERVICE_AUTH_MARKERS):
        return "service_auth"

    auth_middleware = detect_auth_middleware(facts.middleware_refs)
    if auth_middleware:
        return "middleware_auth"

    if _match_markers(refs, _USER_AUTH_MARKERS):
        return "user_auth"

    if _match_markers(refs, _AUTH_AMBIGUOUS_MARKERS):
        return "ambiguous"

    return "missing"


def classify_ownership_mode(endpoint: BackendEndpoint) -> str:
    path = endpoint.canonical_path or canonicalize_path(endpoint.path)
    if "{" not in path:
        return "not_applicable"
    # Catch-all router parameters (e.g. /{path:path}) do not represent a
    # concrete resource identifier and should not trigger ownership checks.
    if re.search(r"\{[^}:]+:path\}", path):
        return "not_applicable"

    if (endpoint.route_intent or "") in {"public_meta", "auth_entry"}:
        return "not_applicable"

    refs = _combined_refs(endpoint, None)
    joined = " ".join(refs)
    path_params = extract_path_params(path)
    has_identity = any(marker in joined for marker in ("current_user", "user_id", "tenant_id", "org_id", "owner_id"))
    has_resource_param = any(param in joined for param in path_params)

    if _match_markers(refs, _OWNERSHIP_MARKERS):
        return "covered"
    if any(pattern.search(joined) for pattern in _OWNERSHIP_COVERED_PATTERNS):
        return "covered"
    if has_identity and has_resource_param:
        return "covered"
    if _match_markers(refs, _OWNERSHIP_AMBIGUOUS_MARKERS):
        return "ambiguous"
    return "missing"


def detect_auth_middleware(middleware_refs: list[str]) -> list[str]:
    matched: list[str] = []
    for ref in middleware_refs:
        lowered = ref.lower()
        if any(keyword in lowered for keyword in _AUTH_MIDDLEWARE_KEYWORDS):
            matched.append(ref)
    return matched


def extract_path_params(path: str) -> list[str]:
    return [match.group(1) for match in re.finditer(r"\{([^}:]+)(?::[^}]+)?\}", path)]


def _combined_refs(endpoint: BackendEndpoint, facts: FastAPIGlobalFacts | None) -> list[str]:
    refs = [
        *endpoint.dependencies,
        *endpoint.decorators,
        *endpoint.call_refs,
        *endpoint.string_refs,
    ]
    if endpoint.function_name:
        refs.append(endpoint.function_name)
    if endpoint.request_schema:
        refs.append(endpoint.request_schema)
    if endpoint.response_schema:
        refs.append(endpoint.response_schema)
    if facts is not None:
        refs.extend(facts.middleware_refs)
        refs.extend(facts.global_dependencies)
        refs.extend(facts.module_call_refs)
    return [ref.strip().lower() for ref in refs if ref and ref.strip()]


def _match_markers(refs: list[str], markers: frozenset[str]) -> list[str]:
    joined = " ".join(refs)
    return [marker for marker in markers if marker in joined]
