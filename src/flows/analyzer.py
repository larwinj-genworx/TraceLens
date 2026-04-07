from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from src.constants.defaults import is_sensitive_field_name
from src.flows.catalog import FlowCatalogLoader
from src.schemas.internal import (
    BackendEndpoint,
    FlowCoverageItem,
    FlowRuleDefinition,
    FlowStatus,
    FlowSummaryItem,
    MandatoryFlowResult,
    Observation,
    RuntimeExecutionResult,
    StaticAnalysisResult,
)
from src.utils.canonicalization import (
    canonicalize_path,
    classify_auth_mode,
    classify_ownership_mode,
    classify_route_intent,
    detect_auth_middleware,
)


class MandatoryFlowAnalyzer:
    def __init__(self, catalog_loader: FlowCatalogLoader | None = None) -> None:
        self.catalog_loader = catalog_loader or FlowCatalogLoader()

    def evaluate(
        self,
        static_results: dict[str, StaticAnalysisResult],
        runtime_result: RuntimeExecutionResult | None = None,
    ) -> MandatoryFlowResult:
        catalog = self.catalog_loader.load()

        definitions = {flow.id: flow for flow in catalog.flows}
        coverage: list[FlowCoverageItem] = []
        observations: list[Observation] = []

        probe_index = self._build_probe_index(runtime_result)

        for service, static in static_results.items():
            if not static.backend_endpoints:
                continue

            global_refs = self._normalize_values(
                static.fastapi_facts.middleware_refs
                + static.fastapi_facts.exception_handler_refs
                + static.fastapi_facts.global_dependencies
                + static.fastapi_facts.module_call_refs
            )

            auth_middleware = self._detect_auth_middleware(static.fastapi_facts.middleware_refs)

            for endpoint in static.backend_endpoints:
                endpoint.canonical_path = endpoint.canonical_path or canonicalize_path(endpoint.path)
                endpoint_refs = self._build_endpoint_refs(endpoint)
                endpoint.route_intent = endpoint.route_intent or classify_route_intent(
                    endpoint.path,
                    endpoint.method,
                    endpoint_refs + global_refs,
                )
                endpoint.auth_mode = classify_auth_mode(endpoint, static.fastapi_facts)
                endpoint.ownership_mode = classify_ownership_mode(endpoint)
                is_public = self._is_public_endpoint(
                    endpoint.path,
                    catalog.public_path_markers,
                    endpoint.route_intent,
                )
                is_mutating = endpoint.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
                sensitive_response_fields = [
                    field.name
                    for field in endpoint.response_fields
                    if is_sensitive_field_name(field.name)
                ]
                combined_refs = sorted(set(endpoint_refs + global_refs))

                for flow in catalog.flows:
                    applicable = self._is_applicable(
                        flow=flow,
                        endpoint=endpoint,
                        is_public=is_public,
                        is_mutating=is_mutating,
                        refs=combined_refs,
                        sensitive_response_fields=sensitive_response_fields,
                    )
                    if not applicable:
                        coverage.append(
                            FlowCoverageItem(
                                flow_id=flow.id,
                                service=service,
                                endpoint=f"{endpoint.method} {endpoint.path}",
                                file=endpoint.file,
                                line=endpoint.line,
                                status=FlowStatus.NOT_APPLICABLE,
                                confidence=1.0,
                                evidence={"reason": "not_applicable"},
                            )
                        )
                        continue

                    status, confidence, evidence = self._evaluate_flow(
                        flow, endpoint, combined_refs, sensitive_response_fields,
                        auth_middleware=auth_middleware,
                    )
                    confidence = self._enrich_confidence(
                        status=status,
                        confidence=confidence,
                        endpoint=endpoint,
                        probe_index=probe_index,
                    )

                    item = FlowCoverageItem(
                        flow_id=flow.id,
                        service=service,
                        endpoint=f"{endpoint.method} {endpoint.path}",
                        file=endpoint.file,
                        line=endpoint.line,
                        status=status,
                        confidence=confidence,
                        evidence=evidence,
                    )
                    coverage.append(item)

                    if status == FlowStatus.AMBIGUOUS:
                        observations.append(
                            Observation(
                                flow_id=flow.id,
                                service=service,
                                endpoint=item.endpoint,
                                file=item.file,
                                line=item.line,
                                message=f"{flow.title} coverage is ambiguous for this endpoint.",
                                confidence=confidence,
                                evidence=evidence,
                            )
                        )

        summary = self._summarize_coverage(catalog.flows, coverage)
        return MandatoryFlowResult(
            catalog_version=catalog.version,
            flow_definitions=definitions,
            flow_coverage=coverage,
            flow_summary=summary,
            observations=observations,
        )

    def _is_public_endpoint(
        self,
        path: str,
        public_markers: list[str],
        route_intent: str | None = None,
    ) -> bool:
        """
        Return True when *path* is considered a public (unauthenticated) endpoint.

        Matching strategy (in order):
        1. Exact string match.
        2. Segment-aware sliding-window match: any contiguous window of segments
           in the candidate path that equals the marker's segments counts as a
           match.  This handles the common pattern where a global ``/api`` (or
           ``/api/v1``) prefix is prepended to all routes:
             - ``/api/auth/login`` matches marker ``/auth``  ✓
             - ``/api/v1/login``   matches marker ``/login`` ✓
             - ``/api/login_history`` does NOT match ``/login`` because
               ``login_history`` ≠ ``login`` in exact segment comparison ✓
        """
        if route_intent in {"public_meta", "auth_entry"}:
            return True

        normalized = canonicalize_path(path).strip()
        if not normalized:
            return False
        if normalized in public_markers:
            return True

        candidate_parts = [p for p in normalized.split("/") if p]

        for marker in public_markers:
            marker_parts = [p for p in marker.split("/") if p]
            if not marker_parts:
                continue
            depth = len(marker_parts)
            if len(candidate_parts) < depth:
                continue
            # Slide a window of `depth` segments across the candidate path.
            for i in range(len(candidate_parts) - depth + 1):
                if candidate_parts[i : i + depth] == marker_parts:
                    return True

        return False

    def _build_endpoint_refs(self, endpoint: BackendEndpoint) -> list[str]:
        refs = []
        refs.extend(endpoint.dependencies)
        refs.extend(endpoint.decorators)
        refs.extend(endpoint.call_refs)
        refs.extend(endpoint.string_refs)
        if endpoint.function_name:
            refs.append(endpoint.function_name)
        if endpoint.request_schema:
            refs.append(endpoint.request_schema)
        if endpoint.response_schema:
            refs.append(endpoint.response_schema)
        return self._normalize_values(refs)

    def _normalize_values(self, values: Iterable[str]) -> list[str]:
        normalized: list[str] = []
        for value in values:
            lowered = value.strip().lower()
            if lowered:
                normalized.append(lowered)
        return normalized

    def _is_applicable(
        self,
        flow: FlowRuleDefinition,
        endpoint: BackendEndpoint,
        is_public: bool,
        is_mutating: bool,
        refs: list[str],
        sensitive_response_fields: list[str],
    ) -> bool:
        applies = flow.applies_to
        method = endpoint.method.upper()

        # WebSocket endpoints only participate in flows that explicitly list "WS"
        # in their methods or use the wildcard "*".
        if endpoint.is_websocket:
            methods_upper = [m.upper() for m in applies.methods]
            if "WS" not in methods_upper and "*" not in methods_upper:
                return False

        methods = [item.upper() for item in applies.methods]
        if methods and "*" not in methods and method not in methods:
            return False

        if applies.only_public and not is_public:
            return False
        if not applies.include_public and is_public:
            return False
        if applies.requires_mutating and not is_mutating:
            return False
        if applies.requires_sensitive_response and not sensitive_response_fields:
            return False

        # Exclude specific path patterns (e.g. health checks, monitoring endpoints)
        if applies.exclude_path_markers:
            for excl in applies.exclude_path_markers:
                excl_parts = [p for p in excl.split("/") if p]
                candidate_parts = [p for p in endpoint.path.split("/") if p]
                if not excl_parts:
                    continue
                depth = len(excl_parts)
                if candidate_parts[:depth] == excl_parts:
                    return False

        if applies.path_markers_any:
            has_marker = any(marker.lower() in endpoint.path.lower() for marker in applies.path_markers_any)
            if applies.requires_path_markers and not has_marker:
                return False

        if applies.requires_sink:
            sink_markers = flow.sink_markers or []
            if not self._has_any_marker(refs, sink_markers):
                return False

        if applies.requires_auth_sensitive:
            auth_markers = ["auth", "get_current", "session", "permission", "scope", "role"]
            if is_public and not self._has_any_marker(refs, auth_markers):
                return False

        # secret_pii_protection_flow: only applicable when the endpoint actually
        # exposes sensitive fields in its response schema.  Ref-based signals
        # (e.g. logger calls containing the substring "log") are too noisy and
        # lead to false positives on health/utility endpoints.
        if flow.id == "secret_pii_protection_flow":
            if not sensitive_response_fields:
                return False

        if flow.id == "response_contract_flow" and endpoint.method.upper() == "HEAD":
            return False

        if flow.id == "rate_limit_flow" and (endpoint.route_intent or "") != "auth_entry":
            return False

        return True

    def _evaluate_flow(
        self,
        flow: FlowRuleDefinition,
        endpoint: BackendEndpoint,
        refs: list[str],
        sensitive_response_fields: list[str],
        auth_middleware: list[str] | None = None,
    ) -> tuple[FlowStatus, float, dict]:
        covered_markers = flow.covered_markers
        ambiguous_markers = flow.ambiguous_markers

        covered_hits = self._matched_markers(refs, covered_markers)
        ambiguous_hits = self._matched_markers(refs, ambiguous_markers)

        # ── Authentication flow: check deps, decorator/router deps, and middleware
        # We use endpoint.dependencies directly (covers arg-injected "arg:func",
        # decorator "dependencies=[Depends(func)]", and router-level deps) rather
        # than filtering combined_refs by ":" which missed decorator/router deps.
        # After dependency checks, we also check for auth middleware registered on
        # the service (e.g. JWTMiddleware) which provides global auth coverage.
        if flow.id == "authn_flow":
            base_evidence = {
                "auth_mode": endpoint.auth_mode,
                "route_intent": endpoint.route_intent,
                "canonical_path": endpoint.canonical_path,
                "auth_deps": endpoint.dependencies,
            }
            if endpoint.auth_mode == "public":
                return (
                    FlowStatus.COVERED,
                    1.0,
                    {**base_evidence, "covered_by": ["public_route"]},
                )
            if endpoint.auth_mode == "service_auth":
                return (
                    FlowStatus.COVERED,
                    0.94,
                    {**base_evidence, "covered_by": ["service_auth"]},
                )
            if endpoint.auth_mode == "middleware_auth":
                return (
                    FlowStatus.COVERED,
                    0.90,
                    {
                        **base_evidence,
                        "auth_middleware": auth_middleware,
                        "covered_by": ["middleware"],
                    },
                )
            if endpoint.auth_mode == "user_auth":
                return (
                    FlowStatus.COVERED,
                    0.92,
                    {**base_evidence, "covered_by": covered_hits or ["user_auth"]},
                )
            if endpoint.auth_mode == "ambiguous":
                return (
                    FlowStatus.AMBIGUOUS,
                    0.58,
                    {**base_evidence, "ambiguous_hints": ambiguous_hits or ["identity_marker"]},
                )

            dep_refs = self._normalize_values(endpoint.dependencies)
            dep_covered = self._matched_markers(dep_refs, covered_markers)
            if dep_covered:
                return (
                    FlowStatus.COVERED,
                    0.92,
                    {**base_evidence, "covered_by": dep_covered},
                )

            if auth_middleware:
                return (
                    FlowStatus.COVERED,
                    0.90,
                    {
                        **base_evidence,
                        "auth_middleware": auth_middleware,
                        "covered_by": "middleware",
                    },
                )

            dep_ambiguous = self._matched_markers(dep_refs, ambiguous_markers)
            if dep_ambiguous:
                return (
                    FlowStatus.AMBIGUOUS,
                    0.58,
                    {**base_evidence, "ambiguous_hints": dep_ambiguous},
                )
            return (
                FlowStatus.MISSING,
                0.88,
                {**base_evidence, "reason": "no_auth_dependency_found"},
            )

        if flow.id == "ownership_flow":
            base_evidence = {
                "ownership_mode": endpoint.ownership_mode,
                "route_intent": endpoint.route_intent,
                "canonical_path": endpoint.canonical_path,
            }
            if endpoint.ownership_mode == "covered":
                return (
                    FlowStatus.COVERED,
                    0.9,
                    {**base_evidence, "covered_hits": covered_hits or endpoint.call_refs[:8]},
                )
            if endpoint.ownership_mode == "ambiguous":
                return (
                    FlowStatus.AMBIGUOUS,
                    0.58,
                    {**base_evidence, "ambiguous_hits": ambiguous_hits or endpoint.call_refs[:8]},
                )
            return (
                FlowStatus.MISSING,
                0.86,
                {**base_evidence, "covered_hits": covered_hits, "ambiguous_hits": ambiguous_hits},
            )

        if flow.id == "request_validation_flow":
            if endpoint.request_schema:
                return (
                    FlowStatus.COVERED,
                    0.94,
                    {"request_schema": endpoint.request_schema, "covered_by": ["request_schema"]},
                )

        if flow.id == "response_contract_flow":
            if endpoint.response_schema or endpoint.response_fields:
                return (
                    FlowStatus.COVERED,
                    0.93,
                    {
                        "response_schema": endpoint.response_schema,
                        "response_field_count": len(endpoint.response_fields),
                        "covered_by": ["response_model"],
                    },
                )

        if flow.id == "error_handling_flow" and endpoint.has_try_except:
            return (
                FlowStatus.COVERED,
                0.88,
                {
                    "route_intent": endpoint.route_intent,
                    "canonical_path": endpoint.canonical_path,
                    "covered_by": ["try_except"],
                },
            )

        if flow.id == "input_sanitization_flow":
            sink_hits = self._matched_markers(refs, flow.sink_markers)
            sanitizer_hits = self._matched_markers(refs, flow.sanitizer_markers)
            if sink_hits and sanitizer_hits:
                return (
                    FlowStatus.COVERED,
                    0.78,
                    {"sink_hits": sink_hits, "sanitizer_hits": sanitizer_hits},
                )
            if sink_hits and not sanitizer_hits:
                if ambiguous_hits:
                    return (
                        FlowStatus.AMBIGUOUS,
                        0.58,
                        {"sink_hits": sink_hits, "ambiguous_hits": ambiguous_hits},
                    )
                return (
                    FlowStatus.MISSING,
                    0.87,
                    {
                        "route_intent": endpoint.route_intent,
                        "canonical_path": endpoint.canonical_path,
                        "sink_hits": sink_hits,
                        "sanitizer_hits": [],
                    },
                )

        if flow.id == "secret_pii_protection_flow" and sensitive_response_fields:
            if covered_hits:
                return (
                    FlowStatus.COVERED,
                    0.86,
                    {
                        "sensitive_fields": sensitive_response_fields,
                        "covered_hits": covered_hits,
                    },
                )
            if ambiguous_hits:
                return (
                    FlowStatus.AMBIGUOUS,
                    0.56,
                    {
                        "sensitive_fields": sensitive_response_fields,
                        "ambiguous_hits": ambiguous_hits,
                    },
                )
            return (
                FlowStatus.MISSING,
                0.9,
                {
                    "sensitive_fields": sensitive_response_fields,
                    "covered_hits": [],
                },
            )

        if covered_hits:
            return (
                FlowStatus.COVERED,
                0.82,
                {
                    "route_intent": endpoint.route_intent,
                    "canonical_path": endpoint.canonical_path,
                    "covered_hits": covered_hits,
                },
            )

        if ambiguous_hits:
            return (
                FlowStatus.AMBIGUOUS,
                0.55,
                {
                    "route_intent": endpoint.route_intent,
                    "canonical_path": endpoint.canonical_path,
                    "ambiguous_hits": ambiguous_hits,
                },
            )

        return (
            FlowStatus.MISSING,
            0.84,
            {
                "route_intent": endpoint.route_intent,
                "canonical_path": endpoint.canonical_path,
                "covered_hits": [],
                "ambiguous_hits": [],
            },
        )

    def _has_any_marker(self, refs: list[str], markers: list[str]) -> bool:
        return bool(self._matched_markers(refs, markers))

    def _matched_markers(self, refs: list[str], markers: list[str]) -> list[str]:
        hits: set[str] = set()
        for marker in markers:
            needle = marker.lower()
            for ref in refs:
                if needle in ref:
                    hits.add(marker)
                    break
        return sorted(hits)

    def _detect_auth_middleware(self, middleware_refs: list[str]) -> list[str]:
        """Return middleware names that indicate authentication enforcement."""
        return detect_auth_middleware(middleware_refs)

    def _summarize_coverage(
        self,
        flows: list[FlowRuleDefinition],
        coverage: list[FlowCoverageItem],
    ) -> list[FlowSummaryItem]:
        grouped: dict[str, dict[str, int]] = defaultdict(lambda: defaultdict(int))
        title_by_flow = {flow.id: flow.title for flow in flows}

        for item in coverage:
            grouped[item.flow_id][item.status.value] += 1

        summary: list[FlowSummaryItem] = []
        for flow in flows:
            counts = grouped.get(flow.id, {})
            summary.append(
                FlowSummaryItem(
                    flow_id=flow.id,
                    title=title_by_flow.get(flow.id, flow.id),
                    covered=counts.get(FlowStatus.COVERED.value, 0),
                    missing=counts.get(FlowStatus.MISSING.value, 0),
                    ambiguous=counts.get(FlowStatus.AMBIGUOUS.value, 0),
                    not_applicable=counts.get(FlowStatus.NOT_APPLICABLE.value, 0),
                )
            )
        return summary

    def _build_probe_index(
        self,
        runtime_result: RuntimeExecutionResult | None,
    ) -> dict[tuple[str, str], tuple[int | None, str | None]]:
        if not runtime_result:
            return {}
        index: dict[tuple[str, str], tuple[int | None, str | None]] = {}
        for probe in runtime_result.probes:
            index[(probe.method.upper(), canonicalize_path(self._extract_path(probe.url)))] = (probe.status_code, probe.error)
        return index

    def _extract_path(self, url: str) -> str:
        if not url:
            return "/"
        start = url.find("//")
        if start == -1:
            return url if url.startswith("/") else f"/{url}"
        slash = url.find("/", start + 2)
        if slash == -1:
            return "/"
        path = url[slash:]
        query_start = path.find("?")
        return path if query_start == -1 else path[:query_start]

    def _enrich_confidence(
        self,
        status: FlowStatus,
        confidence: float,
        endpoint: BackendEndpoint,
        probe_index: dict[tuple[str, str], tuple[int | None, str | None]],
    ) -> float:
        key = (endpoint.method.upper(), endpoint.canonical_path or canonicalize_path(endpoint.path))
        status_code, error = probe_index.get(key, (None, None))

        updated = confidence
        if status == FlowStatus.COVERED and status_code is not None and 200 <= status_code < 300:
            updated += 0.05
        elif status == FlowStatus.MISSING and (error or (status_code is not None and status_code >= 500)):
            updated += 0.05
        elif status == FlowStatus.AMBIGUOUS and status_code is not None and 200 <= status_code < 300:
            updated += 0.03

        if updated < 0.0:
            return 0.0
        if updated > 1.0:
            return 1.0
        return round(updated, 3)
