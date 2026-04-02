from __future__ import annotations

from collections import defaultdict
from typing import Iterable

from src.constants.defaults import SENSITIVE_FIELD_MARKERS
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

            for endpoint in static.backend_endpoints:
                endpoint_refs = self._build_endpoint_refs(endpoint)
                is_public = self._is_public_endpoint(endpoint.path, catalog.public_path_markers)
                is_mutating = endpoint.method.upper() in {"POST", "PUT", "PATCH", "DELETE"}
                sensitive_response_fields = [
                    field.name
                    for field in endpoint.response_fields
                    if any(marker in field.name.lower() for marker in SENSITIVE_FIELD_MARKERS)
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

                    status, confidence, evidence = self._evaluate_flow(flow, endpoint, combined_refs, sensitive_response_fields)
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

    def _is_public_endpoint(self, path: str, public_markers: list[str]) -> bool:
        normalized = path.strip()
        if not normalized:
            return False
        if normalized in public_markers:
            return True
        return any(normalized.startswith(marker) for marker in public_markers)

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

        if applies.path_markers_any:
            has_marker = any(marker.lower() in endpoint.path.lower() for marker in applies.path_markers_any)
            if applies.requires_path_markers and not has_marker:
                return False
            if flow.id == "rate_limit_flow":
                # For rate limit, evaluate public paths and auth paths.
                if not is_public and not has_marker:
                    return False

        if applies.requires_sink:
            sink_markers = flow.sink_markers or []
            if not self._has_any_marker(refs, sink_markers):
                return False

        if applies.requires_auth_sensitive:
            auth_markers = ["auth", "jwt", "token", "session", "permission", "scope", "role"]
            if is_public and not self._has_any_marker(refs, auth_markers):
                return False

        if flow.id == "secret_pii_protection_flow":
            has_sensitive_signals = bool(sensitive_response_fields) or self._has_any_marker(
                refs,
                ["password", "secret", "token", "ssn", "credit", "authorization", "log"],
            )
            if not has_sensitive_signals:
                return False

        if flow.id == "response_contract_flow" and endpoint.method.upper() == "HEAD":
            return False

        return True

    def _evaluate_flow(
        self,
        flow: FlowRuleDefinition,
        endpoint: BackendEndpoint,
        refs: list[str],
        sensitive_response_fields: list[str],
    ) -> tuple[FlowStatus, float, dict]:
        covered_markers = flow.covered_markers
        ambiguous_markers = flow.ambiguous_markers

        covered_hits = self._matched_markers(refs, covered_markers)
        ambiguous_hits = self._matched_markers(refs, ambiguous_markers)

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
                {"covered_by": ["try_except"]},
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
                    {"sink_hits": sink_hits, "sanitizer_hits": []},
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
                {"covered_hits": covered_hits},
            )

        if ambiguous_hits:
            return (
                FlowStatus.AMBIGUOUS,
                0.55,
                {"ambiguous_hits": ambiguous_hits},
            )

        return (
            FlowStatus.MISSING,
            0.84,
            {"covered_hits": [], "ambiguous_hits": []},
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
            index[(probe.method.upper(), self._extract_path(probe.url))] = (probe.status_code, probe.error)
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
        key = (endpoint.method.upper(), endpoint.path)
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
