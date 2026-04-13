"""Generic strict standards evidence collectors for all categories."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable

from src.schemas.internal import BackendEndpoint, FrontendCall, StaticAnalysisResult
from src.standards.evidence_collectors.ast_code_index import (
    ASTCodeIndex,
    ASTHit,
    resolve_marker_hits,
)
from src.standards.evidence_collectors.base import CategoryEvidenceResult, Evidence
from src.standards.resolver import CategoryResolution, MarkerItem, ResolvedStandard


_FASTAPI_EXTENSIONS = (".py",)
_REACT_EXTENSIONS = (".ts", ".tsx", ".js", ".jsx")
_IGNORED_DIRS = frozenset({
    ".git", "node_modules", "dist", "build",
    ".venv", "venv", "__pycache__", ".pytest_cache",
})
_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}
_READ_WRITE_METHODS = {"GET", "POST", "PUT", "PATCH", "DELETE"}
_PUBLIC_AUTH_PATHS = frozenset({
    "/health",
    "/healthz",
    "/status",
    "/statusz",
    "/docs",
    "/redoc",
    "/openapi",
    "/openapi.json",
    "/metrics",
    "/readiness",
    "/liveness",
    "/ping",
    "/login",
    "/signup",
    "/register",
    "/auth/login",
    "/auth/register",
    "/auth/signup",
    "/token/refresh",
    "/password/reset",
    "/auth/refresh",
    "/auth/logout",
    "/auth/forgot-password",
    "/auth/reset-password",
    "/auth/change-password",
    "/auth/verify",
})

_FASTAPI_ENDPOINT_SCOPED = {
    "auth_style",
    "auth_mechanism",
    "authz_model",
    "authz_enforcement",
    "ownership_protection",
    "request_validation",
    "response_contract",
    "error_handling",
    "rate_limiting",
    "input_sanitization",
    "idempotency",
}

_REACT_CALL_SCOPED = {
    "http_client",
    "api_layer_pattern",
    "auth_token_storage",
}


@dataclass
class MarkerHit:
    file: str
    line: int
    marker: str
    excerpt: str


@dataclass
class RepoCodeIndex:
    repo_paths: dict[str, str]
    _file_cache: dict[tuple[str, str], dict[str, list[str]]] = field(default_factory=dict)
    _marker_cache: dict[tuple[str, str, str], list[MarkerHit]] = field(default_factory=dict)

    def marker_hits(
        self,
        service: str,
        stack: str,
        markers: Iterable[str],
        *,
        file_hint: str | None = None,
    ) -> list[MarkerHit]:
        hits: list[MarkerHit] = []
        for marker in markers:
            if not marker:
                continue
            hits.extend(self._marker_hits_for_marker(service, stack, marker, file_hint=file_hint))
        return hits

    def _marker_hits_for_marker(
        self,
        service: str,
        stack: str,
        marker: str,
        *,
        file_hint: str | None = None,
    ) -> list[MarkerHit]:
        cache_key = (service, stack, marker)
        if cache_key not in self._marker_cache:
            files = self._load_files(service, stack)
            matcher = _build_matcher(marker)
            all_hits: list[MarkerHit] = []
            for rel_path, lines in files.items():
                for idx, line in enumerate(lines, start=1):
                    if matcher(line):
                        all_hits.append(
                            MarkerHit(
                                file=rel_path,
                                line=idx,
                                marker=marker,
                                excerpt=line.strip()[:180],
                            )
                        )
            self._marker_cache[cache_key] = all_hits

        hits = self._marker_cache[cache_key]
        return [h for h in hits if _matches_file_hint(h.file, file_hint)]

    def _load_files(self, service: str, stack: str) -> dict[str, list[str]]:
        key = (service, stack)
        if key in self._file_cache:
            return self._file_cache[key]

        root_raw = self.repo_paths.get(service)
        if not root_raw:
            self._file_cache[key] = {}
            return {}
        root = Path(root_raw)
        if not root.exists():
            self._file_cache[key] = {}
            return {}

        extensions = _FASTAPI_EXTENSIONS if stack == "fastapi" else _REACT_EXTENSIONS
        out: dict[str, list[str]] = {}
        for fpath in root.rglob("*"):
            if not fpath.is_file():
                continue
            if fpath.suffix not in extensions:
                continue
            if any(part in _IGNORED_DIRS for part in fpath.parts):
                continue
            try:
                rel = str(fpath.relative_to(root))
                out[rel] = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                continue
        self._file_cache[key] = out
        return out

    def dependency_chain_marker_hits(
        self,
        service: str,
        dependency_refs: Iterable[str],
        markers: Iterable[str],
    ) -> list[MarkerHit]:
        """Find marker hits in dependency-definition files used by an endpoint."""
        dep_names = _extract_dependency_names(dependency_refs)
        if not dep_names:
            return []
        files = self._load_files(service, "fastapi")
        if not files:
            return []

        definition_files: set[str] = set()
        for dep_name in dep_names:
            dep_pattern = re.compile(rf"\b(?:async\s+def|def)\s+{re.escape(dep_name)}\s*\(")
            for rel_path, lines in files.items():
                if any(dep_pattern.search(line) for line in lines):
                    definition_files.add(rel_path)

        if not definition_files:
            return []

        hits: list[MarkerHit] = []
        for marker in markers:
            if not marker:
                continue
            matcher = _build_matcher(marker)
            for rel_path in sorted(definition_files):
                for idx, line in enumerate(files[rel_path], start=1):
                    if matcher(line):
                        hits.append(
                            MarkerHit(
                                file=rel_path,
                                line=idx,
                                marker=marker,
                                excerpt=line.strip()[:180],
                            )
                        )
                        break
                if hits:
                    break
            if hits:
                break
        return hits


def _get_marker_hits(
    service: str,
    stack: str,
    markers: list[MarkerItem],
    repo_index: RepoCodeIndex,
    ast_index: ASTCodeIndex | None,
    *,
    file_hint: str | None = None,
) -> list[MarkerHit]:
    """Dispatch marker queries to AST index (fastapi) or text index (react).

    Returns MarkerHit objects for a uniform interface.
    """
    use_ast = ast_index is not None and stack == "fastapi" and _has_structured_markers(markers)
    if use_ast:
        ast_hits = resolve_marker_hits(ast_index, service, markers, file_hint=file_hint)
        return [
            MarkerHit(file=h.file, line=h.line, marker=h.marker, excerpt=h.excerpt)
            for h in ast_hits
        ]

    str_markers = _extract_string_markers(markers)
    return repo_index.marker_hits(service, stack, str_markers, file_hint=file_hint)


def _has_structured_markers(markers: list[MarkerItem]) -> bool:
    return any(isinstance(m, dict) for m in markers)


def _extract_string_markers(markers: list[MarkerItem]) -> list[str]:
    """Extract plain string markers, converting dicts to their name/pattern."""
    result: list[str] = []
    for m in markers:
        if isinstance(m, str):
            result.append(m)
        elif isinstance(m, dict):
            result.append(m.get("name", m.get("pattern", "")))
    return [r for r in result if r]


def collect_generic_fastapi_category(
    resolved: ResolvedStandard,
    static_results: dict[str, StaticAnalysisResult],
    category_id: str,
    repo_index: RepoCodeIndex,
    *,
    ast_index: ASTCodeIndex | None = None,
) -> CategoryEvidenceResult:
    category = resolved.fastapi.categories[category_id]
    return _collect_generic_category(
        stack="fastapi",
        category=category,
        static_results=static_results,
        repo_index=repo_index,
        ast_index=ast_index,
        endpoint_scoped=category_id in _FASTAPI_ENDPOINT_SCOPED,
        category_id=category_id,
    )


def collect_generic_react_category(
    resolved: ResolvedStandard,
    static_results: dict[str, StaticAnalysisResult],
    category_id: str,
    repo_index: RepoCodeIndex,
    *,
    ast_index: ASTCodeIndex | None = None,
) -> CategoryEvidenceResult:
    category = resolved.react.categories[category_id]
    return _collect_generic_category(
        stack="react",
        category=category,
        static_results=static_results,
        repo_index=repo_index,
        ast_index=ast_index,
        endpoint_scoped=category_id in _REACT_CALL_SCOPED,
        category_id=category_id,
    )


def _collect_generic_category(
    *,
    stack: str,
    category: CategoryResolution,
    static_results: dict[str, StaticAnalysisResult],
    repo_index: RepoCodeIndex,
    ast_index: ASTCodeIndex | None = None,
    endpoint_scoped: bool,
    category_id: str,
) -> CategoryEvidenceResult:
    style = category.selected_style
    strategy = category.check_strategy
    markers = category.evidence_markers

    result = CategoryEvidenceResult(
        category=category_id,
        declared_style=style,
        overall_status="compliant",
    )

    if not style:
        result.overall_status = "not_applicable"
        result.summary = "No style selected."
        return result

    effective_markers = markers or category.all_option_markers
    expect_absence = _expects_absence(style, strategy)
    external_style = _is_external_style(style, strategy)

    if external_style and not markers:
        result.add(
            Evidence(
                category=category_id,
                style=style,
                status="partial",
                confidence=0.65,
                message="Style is managed externally; static verification is partial.",
                details={"strategy": strategy},
            )
        )
        result.compute_status()
        return result

    if endpoint_scoped:
        for service, static in static_results.items():
            if stack == "fastapi":
                endpoints = _iter_applicable_endpoints(static, category_id)
                for ep in endpoints:
                    endpoint_name = f"{ep.method} {ep.path}"

                    # Pydantic-aware fast path for input_sanitization
                    if category_id == "input_sanitization":
                        if ep.request_schema:
                            result.add(Evidence(
                                category=category_id,
                                style=style,
                                status="compliant",
                                file=ep.file,
                                line=ep.line,
                                endpoint=endpoint_name,
                                service=service,
                                confidence=0.93,
                                message=f"Pydantic model validates input on {endpoint_name}",
                            ))
                            continue
                        if ep.method.upper() in {"GET", "HEAD", "DELETE", "OPTIONS"}:
                            result.add(Evidence(
                                category=category_id,
                                style=style,
                                status="compliant",
                                file=ep.file,
                                line=ep.line,
                                endpoint=endpoint_name,
                                service=service,
                                confidence=0.90,
                                message="Read/delete method — FastAPI type annotations validate params",
                            ))
                            continue
                        if not ep.expects_request_body:
                            result.add(Evidence(
                                category=category_id,
                                style=style,
                                status="compliant",
                                file=ep.file,
                                line=ep.line,
                                endpoint=endpoint_name,
                                service=service,
                                confidence=0.90,
                                message="No request body — nothing to sanitize",
                            ))
                            continue

                    file_hits = _get_marker_hits(
                        service,
                        "fastapi",
                        effective_markers,
                        repo_index,
                        ast_index,
                        file_hint=ep.file,
                    )
                    has_ref_match = _endpoint_refs_match(ep, effective_markers)
                    dependency_hits: list[MarkerHit] = []
                    if (
                        category_id == "auth_mechanism"
                        and not has_ref_match
                        and not file_hits
                    ):
                        dep_str_markers = _extract_string_markers(effective_markers)
                        dependency_hits = repo_index.dependency_chain_marker_hits(
                            service,
                            ep.dependencies,
                            dep_str_markers,
                        )
                    matched = bool(file_hits or has_ref_match or dependency_hits)
                    if expect_absence and matched:
                        first = (file_hits or dependency_hits)[0] if (file_hits or dependency_hits) else None
                        result.add(
                            Evidence(
                                category=category_id,
                                style=style,
                                status="violation",
                                file=first.file if first else ep.file,
                                line=first.line if first else ep.line,
                                endpoint=endpoint_name,
                                service=service,
                                confidence=0.9,
                                message=f"Endpoint violates '{style}' style expectation.",
                                details={"strategy": strategy, "marker": first.marker if first else None},
                            )
                        )
                    elif (not expect_absence) and (not matched):
                        result.add(
                            Evidence(
                                category=category_id,
                                style=style,
                                status="violation",
                                file=ep.file,
                                line=ep.line,
                                endpoint=endpoint_name,
                                service=service,
                                confidence=0.86,
                                message=f"Expected '{style}' markers missing on endpoint {endpoint_name}.",
                                details={"strategy": strategy, "expected_markers": effective_markers[:8]},
                            )
                        )
                    else:
                        first = (file_hits or dependency_hits)[0] if (file_hits or dependency_hits) else None
                        result.add(
                            Evidence(
                                category=category_id,
                                style=style,
                                status="compliant",
                                file=first.file if first else ep.file,
                                line=first.line if first else ep.line,
                                endpoint=endpoint_name,
                                service=service,
                                confidence=0.82,
                                message=f"Endpoint follows '{style}' style.",
                            )
                        )
            else:
                for call in static.frontend_calls:
                    call_ref = f"{call.method.upper()} {call.raw_url}"
                    file_hits = _get_marker_hits(
                        service,
                        "react",
                        effective_markers,
                        repo_index,
                        ast_index,
                        file_hint=call.file,
                    )
                    call_match = _frontend_call_matches(call, effective_markers)
                    matched = bool(file_hits or call_match)
                    if expect_absence and matched:
                        first = file_hits[0] if file_hits else None
                        result.add(
                            Evidence(
                                category=category_id,
                                style=style,
                                status="violation",
                                file=first.file if first else call.file,
                                line=first.line if first else call.line,
                                endpoint=call_ref,
                                service=service,
                                confidence=0.88,
                                message=f"Frontend call violates '{style}' style expectation.",
                                details={"strategy": strategy, "marker": first.marker if first else None},
                            )
                        )
                    elif (not expect_absence) and (not matched):
                        result.add(
                            Evidence(
                                category=category_id,
                                style=style,
                                status="violation",
                                file=call.file,
                                line=call.line,
                                endpoint=call_ref,
                                service=service,
                                confidence=0.84,
                                message=f"Expected '{style}' markers missing in call site.",
                                details={"strategy": strategy, "expected_markers": effective_markers[:8]},
                            )
                        )
                    else:
                        first = file_hits[0] if file_hits else None
                        result.add(
                            Evidence(
                                category=category_id,
                                style=style,
                                status="compliant",
                                file=first.file if first else call.file,
                                line=first.line if first else call.line,
                                endpoint=call_ref,
                                service=service,
                                confidence=0.8,
                                message=f"Frontend call follows '{style}' style.",
                            )
                        )
    else:
        for service in static_results.keys():
            hits = _get_marker_hits(service, stack, effective_markers, repo_index, ast_index)
            matched = bool(hits)
            first = hits[0] if hits else None
            if expect_absence and matched:
                result.add(
                    Evidence(
                        category=category_id,
                        style=style,
                        status="violation",
                        file=first.file if first else "",
                        line=first.line if first else None,
                        service=service,
                        confidence=0.9,
                        message=f"Repository violates '{style}' expectation for {category_id}.",
                        details={"strategy": strategy, "marker": first.marker if first else None},
                    )
                )
            elif (not expect_absence) and (not matched):
                result.add(
                    Evidence(
                        category=category_id,
                        style=style,
                        status="violation",
                        service=service,
                        confidence=0.85,
                        message=f"No evidence for required style '{style}' in category '{category_id}'.",
                        details={"strategy": strategy, "expected_markers": effective_markers[:8]},
                    )
                )
            else:
                result.add(
                    Evidence(
                        category=category_id,
                        style=style,
                        status="compliant",
                        file=first.file if first else "",
                        line=first.line if first else None,
                        service=service,
                        confidence=0.78,
                        message=f"Repository follows '{style}' for category '{category_id}'.",
                    )
                )

    # --- Conflict detection: check if a DIFFERENT style is actually in use ---
    if not expect_absence and category.other_options:
        compliant_count = sum(
            1 for ev in result.evidence_items if ev.status == "compliant"
        )
        for service in static_results.keys():
            conflict = detect_conflicting_style(
                category, repo_index, service, stack,
                ast_index=ast_index,
            )
            if conflict is None:
                continue
            conflicting_style, conflict_hits = conflict
            if not conflict_hits:
                continue
            # If we found more conflicting-style evidence than compliant evidence,
            # the project likely uses a different style than declared.
            if len(conflict_hits) >= max(1, compliant_count // 3):
                for hit in conflict_hits[:5]:
                    result.add(Evidence(
                        category=category_id,
                        style=style,
                        status="violation",
                        file=hit.file,
                        line=hit.line,
                        service=service,
                        confidence=0.88,
                        message=(
                            f"Conflicting style detected: project uses "
                            f"'{conflicting_style}' instead of declared '{style}' "
                            f"(found marker '{hit.marker}')."
                        ),
                        details={
                            "actual_style": conflicting_style,
                            "marker": hit.marker,
                            "excerpt": hit.excerpt,
                        },
                    ))

    result.compute_status()
    return result


def _iter_applicable_endpoints(static: StaticAnalysisResult, category_id: str) -> Iterable[BackendEndpoint]:
    for ep in static.backend_endpoints:
        method = ep.method.upper()
        if category_id in {"auth_style", "auth_mechanism", "authz_model", "authz_enforcement"}:
            if (ep.route_intent or "") in {"public_meta", "auth_entry"}:
                continue
            if (ep.auth_mode or "") == "public":
                continue
            if _is_public_auth_path(ep.path):
                continue
        if category_id in {"request_validation", "authz_model", "authz_enforcement", "idempotency"}:
            if method not in _WRITE_METHODS:
                continue
        elif category_id in {"response_contract"} and method not in _READ_WRITE_METHODS:
            continue
        elif category_id == "ownership_protection" and "{" not in ep.path:
            continue
        elif category_id == "rate_limiting" and method not in {"POST", "PUT", "PATCH", "DELETE", "GET"}:
            continue
        yield ep


def _endpoint_refs_match(endpoint: BackendEndpoint, markers: Iterable[MarkerItem]) -> bool:
    text_parts = [
        endpoint.path,
        endpoint.method,
        endpoint.request_schema or "",
        endpoint.response_schema or "",
        endpoint.function_name or "",
        *endpoint.dependencies,
        *endpoint.decorators,
        *endpoint.call_refs,
        *endpoint.string_refs,
    ]
    haystack = "\n".join(text_parts)
    str_markers = _extract_string_markers(list(markers))
    return any(_marker_match(m, haystack) for m in str_markers)


def _frontend_call_matches(call: FrontendCall, markers: Iterable[MarkerItem]) -> bool:
    text_parts = [
        call.raw_url,
        call.file,
        call.method,
        call.canonical_url or "",
        call.canonical_path or "",
        *call.env_vars,
        *call.payload_fields.keys(),
        *call.headers.keys(),
    ]
    haystack = "\n".join(text_parts)
    str_markers = _extract_string_markers(list(markers))
    return any(_marker_match(m, haystack) for m in str_markers)


def _build_matcher(marker: str):
    regex_mode = bool(re.search(r"\.\*|\(|\)|\[|\]|\||\^|\$", marker))
    if regex_mode:
        try:
            compiled = re.compile(marker, re.IGNORECASE)
            return lambda line: bool(compiled.search(line))
        except re.error:
            pass
    try:
        boundary_re = re.compile(rf"\b{re.escape(marker)}\b", re.IGNORECASE)
        return lambda line: bool(boundary_re.search(line))
    except re.error:
        low = marker.lower()
        return lambda line: low in line.lower()


def _marker_match(marker: str, text: str) -> bool:
    return _build_matcher(marker)(text)


def _expects_absence(style: str, strategy: str) -> bool:
    style_low = style.lower()
    strat_low = strategy.lower()
    return (
        style_low == "none"
        or style_low.startswith("no_")
        or strat_low.startswith("no_")
    )


def _is_external_style(style: str, strategy: str) -> bool:
    combo = f"{style}:{strategy}".lower()
    return any(
        marker in combo
        for marker in (
            "gateway",
            "managed",
            "external",
            "service_auth",
        )
    )


def _matches_file_hint(rel_file: str, file_hint: str | None) -> bool:
    if not file_hint:
        return True
    return rel_file.endswith(file_hint) or file_hint.endswith(rel_file)


def _extract_dependency_names(dependency_refs: Iterable[str]) -> list[str]:
    names: list[str] = []
    for ref in dependency_refs:
        if not ref:
            continue
        raw = ref.split(":", 1)[-1] if ":" in ref else ref
        raw = raw.strip()
        if "(" in raw:
            raw = raw.split("(", 1)[0]
        raw = raw.split(".")[-1].strip()
        if not raw or raw in {"Depends", "Security"}:
            continue
        if raw not in names:
            names.append(raw)
    return names


def _is_public_auth_path(path: str) -> bool:
    normalized = path.lower().rstrip("/")
    if not normalized:
        normalized = "/"
    if normalized in _PUBLIC_AUTH_PATHS:
        return True
    return normalized.startswith(("/health", "/docs", "/openapi", "/metrics"))


def detect_conflicting_style(
    category: CategoryResolution,
    repo_index: RepoCodeIndex,
    service: str,
    stack: str,
    *,
    ast_index: ASTCodeIndex | None = None,
) -> tuple[str, list[MarkerHit]] | None:
    """Check if markers from a non-selected style option are present in the repo.

    Returns (conflicting_style_value, hits) if a conflict is detected,
    or None if no conflict is found.
    """
    if not category.other_options:
        return None

    selected_keys = frozenset(_marker_key(m) for m in category.evidence_markers)
    best: tuple[str, list[MarkerHit]] | None = None
    best_count = 0

    for other_value, other_markers in category.other_options.items():
        if not other_markers:
            continue
        unique_other: list[MarkerItem] = [
            m for m in other_markers
            if _marker_key(m) not in selected_keys
        ]
        if not unique_other:
            continue
        hits = _get_marker_hits(service, stack, unique_other, repo_index, ast_index)
        if len(hits) > best_count:
            best = (other_value, hits)
            best_count = len(hits)

    return best


def _marker_key(marker: MarkerItem) -> str:
    """Produce a comparable key for a marker (string or dict)."""
    if isinstance(marker, str):
        return marker.lower()
    return str(marker).lower()

