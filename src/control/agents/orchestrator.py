from __future__ import annotations

import ast
import inspect
import json
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Awaitable, Callable

import networkx as nx

from src.analyzers.fastapi.parser import FastAPIParser
from src.analyzers.react.parser import ReactParser
from src.config.settings import settings
from src.contracts.validator import ContractValidator
from src.diagnostics.typecheck import TypeDiagnosticsRunner
from src.flows.analyzer import MandatoryFlowAnalyzer
from src.llm.groq_client import GroqClient
from src.observability.logging.setup import get_logger
from src.rules.engine import RuleEngine
from src.runtime.orchestrator import RuntimeOrchestrator
from src.schemas.input import AnalysisRequest
from src.schemas.internal import AnalysisContext, RepoType, RuntimeExecutionResult, StaticAnalysisResult, TypeDiagnostic
from src.schemas.issues import ConfidenceBand, Issue, Severity
from src.schemas.report import AnalysisReport, ReportSummary, StandardsComplianceSection
from src.flows.catalog import FlowCatalogLoader
from src.standards.coverage_tracker import EndpointCoverageTracker
from src.standards.evidence_collectors.collector import StandardsEvidenceCollector
from src.standards.evidence_to_issues import convert_evidence_to_issues
from src.standards.marker_registry import MarkerRegistry
from src.standards.resolver import ResolvedStandard, StandardsResolver
from src.utils.canonicalization import normalize_static_results
from src.utils.env_infer import EnvInferenceEngine
from src.utils.graph_builder import ServiceGraphBuilder
from src.utils.repo_loader import RepoLoader

logger = get_logger(__name__)

ProgressCallback = Callable[[dict[str, Any]], Awaitable[None] | None]


class ValidationOrchestrator:
    def __init__(self) -> None:
        self.repo_loader = RepoLoader()
        self.fastapi_parser = FastAPIParser()
        self.react_parser = ReactParser()
        self.env_engine = EnvInferenceEngine()
        self.graph_builder = ServiceGraphBuilder()
        self.contract_validator = ContractValidator()
        self.mandatory_flow_analyzer = MandatoryFlowAnalyzer()
        self.runtime_orchestrator = RuntimeOrchestrator()
        self.rule_engine = RuleEngine()
        self.groq_client = GroqClient()
        self.type_diagnostics = TypeDiagnosticsRunner()
        self._last_type_diagnostics: list[TypeDiagnostic] = []

    async def run(self, request: AnalysisRequest, progress_cb: ProgressCallback | None = None, job_id: str | None = None) -> AnalysisReport:
        assumptions: list[str] = []

        # Load and resolve TraceLens standard if specified
        resolved_standard: ResolvedStandard | None = None
        standards_context: dict[str, Any] = {}
        if request.standard_id:
            await self._emit(progress_cb, "standards_loading", "Loading TraceLens standard")
            try:
                from src.core.services.standards_service import TraceLensStandardsService
                std_service = TraceLensStandardsService()
                standard = std_service.get_standard(request.standard_id)
                resolver = StandardsResolver()
                resolved_standard = resolver.resolve(standard)
                standards_context = resolved_standard.to_prompt_context()
                assumptions.append(f"Using TraceLens standard: {standard.name} (id: {standard.standard_id})")
                logger.info("orchestrator loaded standard=%s", standard.standard_id)
            except Exception as exc:
                logger.warning("orchestrator failed to load standard %s: %s", request.standard_id, exc)
                assumptions.append(f"Failed to load standard '{request.standard_id}': {exc}")

        await self._emit(progress_cb, "repo_loading", "Loading and cloning repositories")
        repos, load_assumptions = self.repo_loader.load(list(request.repos))
        assumptions.extend(load_assumptions)

        static_results: dict[str, StaticAnalysisResult] = {}
        repo_file_asts: dict[str, dict[str, tuple[Path, ast.Module]]] = {}

        await self._emit(progress_cb, "static_analysis", "Running FastAPI and React static parsers")
        for repo in repos:
            if repo.clone_error:
                static_results[repo.name] = StaticAnalysisResult(
                    repo=repo.name,
                    parser_errors=[f"clone_error: {repo.clone_error}"],
                )
                continue

            fastapi_result = None
            react_result = None
            if repo.repo_type in {RepoType.BACKEND, RepoType.MIXED}:
                fastapi_result, file_asts = self.fastapi_parser.parse(repo.name, repo_path=self._path(repo.local_path))
                repo_file_asts[repo.name] = file_asts
            if repo.repo_type in {RepoType.FRONTEND, RepoType.MIXED}:
                react_result = self.react_parser.parse(repo.name, repo_path=self._path(repo.local_path))

            static_results[repo.name] = self._merge_static_results(repo.name, fastapi_result, react_result)

        # Build the MarkerRegistry for unified marker management
        flow_catalog = FlowCatalogLoader().load()
        marker_registry = MarkerRegistry(
            resolved=resolved_standard,
            flow_catalog=flow_catalog,
        )
        if resolved_standard:
            # Wire public paths from user standard if provided
            from src.core.services.standards_service import TraceLensStandardsService as _StdSvc
            try:
                _std = _StdSvc().get_standard(request.standard_id) if request.standard_id else None
                if _std and _std.public_paths:
                    marker_registry.set_user_public_paths(_std.public_paths)
            except Exception:
                pass

        # Set the active registry for auth evidence collectors
        import src.standards.evidence_collectors.auth_evidence as _auth_ev
        _auth_ev._active_registry = marker_registry

        normalize_static_results(static_results, registry=marker_registry)

        await self._emit(progress_cb, "typecheck", "Running best-effort type diagnostics")
        type_diagnostics = self.type_diagnostics.run(repos)
        self._last_type_diagnostics = type_diagnostics

        await self._emit(progress_cb, "env_inference", "Inferring environment variables and service URLs")
        env_result = self.env_engine.infer(repos, static_results)
        assumptions.extend(env_result.assumptions)

        await self._emit(progress_cb, "graph", "Building service dependency graph")
        graph, graph_result = self.graph_builder.build(repos, static_results, env_result)
        assumptions.extend(self._graph_assumptions(graph, graph_result))

        await self._emit(progress_cb, "contracts", "Executing deterministic contract validation")
        contract_issues = self.contract_validator.validate(graph_result.matches)

        runtime_result: RuntimeExecutionResult | None = None
        if request.enable_runtime:
            await self._emit(progress_cb, "runtime", "Running dockerized integration validation and traffic capture")

            async def runtime_progress(event: dict[str, Any]) -> None:
                await self._emit(
                    progress_cb,
                    stage=event.get("stage", "runtime"),
                    message=event.get("message", "Runtime update"),
                    payload=event.get("payload"),
                )

            runtime_result = await self.runtime_orchestrator.execute(
                repos=repos,
                env_result=env_result,
                graph_result=graph_result,
                timeout_seconds=request.runtime_timeout_seconds,
                progress_cb=runtime_progress,
            )
        
        await self._emit(progress_cb, "data_flow", "Performing end-to-end data flow validation")
        contract_issues.extend(self._validate_data_flow(graph_result, runtime_result))

        # ── Mandatory flows always run (independent of user-selected standards) ──
        # MandatoryFlowAnalyzer uses mandatory_flows_v1.json catalog markers.
        # The resolved standard is only used for supplementary context, not gating.
        await self._emit(progress_cb, "mandatory_flow_index", "Building mandatory-flow coverage index")
        if resolved_standard:
            self.mandatory_flow_analyzer.set_resolved_standard(resolved_standard)
        mandatory_flow_result = self.mandatory_flow_analyzer.evaluate(static_results, runtime_result=runtime_result)
        await self._emit(
            progress_cb,
            "mandatory_flow_eval",
            "Evaluating mandatory flow coverage across coding styles",
            payload={
                "catalog_version": mandatory_flow_result.catalog_version,
                "coverage_count": len(mandatory_flow_result.flow_coverage),
                "observation_count": len(mandatory_flow_result.observations),
            },
        )

        context = AnalysisContext(
            repos=repos,
            static_results=static_results,
            env_result=env_result,
            graph_result=graph_result,
            contract_issues=contract_issues,
            runtime_result=runtime_result,
            flow_catalog_version=mandatory_flow_result.catalog_version,
            flow_definitions=mandatory_flow_result.flow_definitions,
            flow_coverage=mandatory_flow_result.flow_coverage,
            flow_summary=mandatory_flow_result.flow_summary,
            observations=mandatory_flow_result.observations,
            type_diagnostics=type_diagnostics,
        )

        await self._emit(progress_cb, "rules", "Running deterministic rule engine for baseline coverage")
        logger.info("orchestrator running deterministic rules (baseline)")
        deterministic_issues = self.rule_engine.evaluate(context)
        logger.info("orchestrator deterministic_issues=%d", len(deterministic_issues))

        # ── Standards evidence runs ONLY when a user standard is selected ──
        # StandardsEvidenceCollector validates against user-chosen categories.
        # Without a standard, only mandatory flow issues are reported.
        standards_evidence_results = []
        standards_violation_issues: list[Issue] = []
        coverage_matrix_data: dict[str, Any] = {}
        standards_coverage_tracker: EndpointCoverageTracker | None = None
        if (
            resolved_standard
            and resolved_standard.has_standard()
            and settings.strict_standards_mode
        ):
            await self._emit(progress_cb, "standards_check", "Running standards-aware evidence collection")
            evidence_collector = StandardsEvidenceCollector(resolved_standard)
            repo_paths = {r.name: r.local_path for r in repos if r.local_path}
            repo_types = {r.name: r.repo_type.value for r in repos}
            standards_evidence_results = evidence_collector.collect_all(
                static_results,
                repo_paths=repo_paths,
                repo_types=repo_types,
                repo_file_asts=repo_file_asts,
            )

            standards_coverage_tracker = EndpointCoverageTracker(resolved_standard)
            standards_coverage_tracker.build_matrix(
                static_results,
                repo_types=repo_types,
            )
            standards_coverage_tracker.mark_checked(standards_evidence_results)
            coverage_matrix = standards_coverage_tracker.get_matrix()
            coverage_matrix_data = coverage_matrix.to_dict()

            logger.info(
                "orchestrator standards_check categories=%d coverage=%.1f%%",
                len(standards_evidence_results),
                coverage_matrix.coverage_pct,
            )

            standards_violation_issues = convert_evidence_to_issues(
                standards_evidence_results
            )
            if standards_violation_issues:
                deterministic_issues.extend(standards_violation_issues)
                logger.info(
                    "orchestrator standards violations converted=%d",
                    len(standards_violation_issues),
                )

        mode = settings.analysis_mode
        llm_enabled = bool(request.enable_llm_enhancement and settings.groq_api_key)
        use_agentic = llm_enabled and mode in {"agentic", "hybrid"}

        if use_agentic:
            await self._emit(progress_cb, "agentic_analysis", "Running multi-agent LLM analysis workflow")
            logger.info("orchestrator using agentic analysis mode")
            from src.agents.graph import run_analysis_graph

            agentic_issues, agent_observations = await run_analysis_graph(
                context=context,
                progress_cb=progress_cb,
                job_id=job_id,
                standards_context=standards_context,
            )
            assumptions.extend(agent_observations)

            await self._emit(progress_cb, "merge", "Merging deterministic baseline with LLM-enhanced findings")
            issues = self._merge_issues(agentic_issues, deterministic_issues)
            logger.info(
                "orchestrator merged agentic=%d deterministic=%d final=%d",
                len(agentic_issues),
                len(deterministic_issues),
                len(issues),
            )
        else:
            logger.info("orchestrator using deterministic analysis mode")
            issues = deterministic_issues

            if request.enable_llm_enhancement:
                await self._emit(progress_cb, "llm", "Enhancing explanations and fixes via Groq")
                issues = await self.groq_client.enhance_issues(issues)

        # Run 4-layer false positive elimination pipeline if standards are active
        if (
            resolved_standard
            and resolved_standard.has_standard()
            and standards_evidence_results
            and settings.strict_standards_mode
        ):
            from src.standards.filters.pipeline import run_false_positive_pipeline
            pre_fp_count = len(issues)
            issues = run_false_positive_pipeline(
                issues, resolved_standard, standards_evidence_results
            )
            logger.info(
                "orchestrator fp_pipeline reduced issues %d -> %d",
                pre_fp_count,
                len(issues),
            )

        issues, advisories = self._finalize_issues(issues)

        await self._emit(progress_cb, "report", "Building final report")
        summary = self._build_summary(issues)

        assumptions.extend(self._residual_assumptions(repos, static_results, runtime_result))

        standards_compliance_sections: list[StandardsComplianceSection] = []
        folder_structure_compliance: StandardsComplianceSection | None = None
        mandatory_compliance_sections: list[StandardsComplianceSection] = []
        issue_by_category: dict[str, list[Issue]] = {}
        for issue in issues:
            cat = self._extract_standards_category(issue)
            if not cat:
                continue
            issue_by_category.setdefault(cat, []).append(issue)

        # Run accuracy validation and coverage verification
        if (
            resolved_standard
            and resolved_standard.has_standard()
            and settings.strict_standards_mode
        ):
            from src.diagnostics.accuracy_validator import AccuracyValidator
            from src.standards.coverage_verifier import CoverageVerifier

            accuracy_validator = AccuracyValidator(resolved_standard)
            accuracy_result = accuracy_validator.validate(issues, standards_evidence_results)
            if accuracy_result.warnings:
                assumptions.extend(
                    [f"[accuracy] {w}" for w in accuracy_result.warnings]
                )
            if job_id:
                accuracy_validator.dump_trace(job_id, accuracy_result)

            cov_verifier = CoverageVerifier(resolved_standard)
            coverage_matrix_obj = (
                standards_coverage_tracker.get_matrix()
                if standards_coverage_tracker
                else None
            )
            cov_result = cov_verifier.verify(
                static_results,
                standards_evidence_results,
                coverage_matrix=coverage_matrix_obj,
            )
            if cov_result.warnings:
                assumptions.extend(
                    [f"[coverage] {w}" for w in cov_result.warnings]
                )

            logger.info(
                "orchestrator accuracy=%.1f%% coverage=%.1f%%",
                accuracy_result.accuracy_score,
                cov_result.coverage_pct,
            )

        # Build standards compliance sections for report model.
        for ev_result in standards_evidence_results:
            section = StandardsComplianceSection(
                category=ev_result.category,
                declared_style=ev_result.declared_style,
                status=ev_result.overall_status,
                confidence=round(ev_result.confidence, 2),
                evidence_count=len(ev_result.evidence_items),
                violations=sum(1 for e in ev_result.evidence_items if e.status == "violation"),
                compliant=sum(1 for e in ev_result.evidence_items if e.status == "compliant"),
                summary=ev_result.summary,
                findings=issue_by_category.get(ev_result.category, []),
                evidence_summary=[
                    {
                        "status": e.status,
                        "file": e.file,
                        "line": e.line,
                        "endpoint": e.endpoint,
                        "service": e.service,
                        "message": e.message,
                        "confidence": round(e.confidence, 2),
                    }
                    for e in ev_result.evidence_items
                ],
            )
            if ev_result.category == "folder_structure":
                folder_structure_compliance = section
            else:
                standards_compliance_sections.append(section)

        flow_issue_map = {
            "authn_flow": "missing_auth",
            "authz_flow": "missing_authz_flow",
            "ownership_flow": "missing_ownership_check",
            "request_validation_flow": "missing_validation",
            "response_contract_flow": "missing_response_contract_flow",
            "error_handling_flow": "missing_error_handling_flow",
            "input_sanitization_flow": "missing_input_sanitization_flow",
            "secret_pii_protection_flow": "missing_secret_pii_protection_flow",
            "rate_limit_flow": "missing_rate_limit_flow",
            "audit_trace_flow": "missing_audit_trace_flow",
            "idempotency_tx_flow": "missing_idempotency_tx_flow",
        }
        for flow_item in mandatory_flow_result.flow_summary:
            mapped_issue_type = flow_issue_map.get(flow_item.flow_id, flow_item.flow_id)
            findings = [issue for issue in issues if issue.type == mapped_issue_type]
            status = "compliant"
            if flow_item.missing > 0:
                status = "non_compliant"
            elif flow_item.ambiguous > 0:
                status = "partial"
            total_checks = (
                flow_item.covered
                + flow_item.missing
                + flow_item.ambiguous
                + flow_item.not_applicable
            )
            confidence = (
                flow_item.covered / max(flow_item.covered + flow_item.missing + flow_item.ambiguous, 1)
            )
            mandatory_compliance_sections.append(
                StandardsComplianceSection(
                    category=flow_item.flow_id,
                    declared_style="mandatory_rule",
                    status=status,
                    confidence=round(confidence, 2),
                    evidence_count=total_checks,
                    violations=flow_item.missing,
                    compliant=flow_item.covered,
                    summary=flow_item.title,
                    findings=findings,
                    evidence_summary=[],
                )
            )

        report = AnalysisReport(
            summary=summary,
            assumptions=sorted(set(assumptions)),
            issues=issues,
            advisories=advisories,
            type_diagnostics=type_diagnostics,
            provenance_summary=self._provenance_summary(issues, advisories),
            flow_summary=mandatory_flow_result.flow_summary,
            flow_coverage=mandatory_flow_result.flow_coverage,
            observations=mandatory_flow_result.observations,
            standard_used=request.standard_id,
            standards_compliance=standards_compliance_sections,
            folder_structure_compliance=folder_structure_compliance,
            mandatory_compliance=mandatory_compliance_sections,
            coverage_matrix=coverage_matrix_data,
        )

        self._write_final_trace(job_id, report)

        await self._emit(progress_cb, "complete", "Analysis completed", payload={"summary": summary.model_dump()})
        return report

    def _extract_standards_category(self, issue: Issue) -> str | None:
        if not issue.type.startswith("standards_violation_"):
            return None
        stripped = issue.type.removeprefix("standards_violation_")
        if not stripped:
            return None
        for part in [
            "auth_style",
            "auth_mechanism",
            "authz_model",
            "authz_enforcement",
            "ownership_protection",
            "request_validation",
            "response_contract",
            "error_handling",
            "database_orm",
            "persistence_pattern",
            "logging_style",
            "logging_library",
            "rate_limiting",
            "cors_config",
            "cors_policy",
            "api_architecture",
            "api_versioning",
            "config_management",
            "migration_tool",
            "di_style",
            "architecture_pattern",
            "input_sanitization",
            "secret_management",
            "idempotency",
            "state_management",
            "http_client",
            "routing",
            "auth_token_storage",
            "form_handling",
            "component_architecture",
            "styling_approach",
            "error_boundary",
            "api_layer_pattern",
            "env_config",
            "folder_structure",
        ]:
            if stripped.startswith(part):
                return part
        return None

    def _merge_static_results(
        self,
        repo_name: str,
        fastapi_result: StaticAnalysisResult | None,
        react_result: StaticAnalysisResult | None,
    ) -> StaticAnalysisResult:
        if fastapi_result and not react_result:
            return fastapi_result
        if react_result and not fastapi_result:
            return react_result
        if not fastapi_result and not react_result:
            return StaticAnalysisResult(repo=repo_name)

        assert fastapi_result is not None
        assert react_result is not None

        return StaticAnalysisResult(
            repo=repo_name,
            backend_endpoints=fastapi_result.backend_endpoints,
            frontend_calls=react_result.frontend_calls,
            env_references=sorted(set(fastapi_result.env_references + react_result.env_references)),
            hardcoded_urls=sorted(set(fastapi_result.hardcoded_urls + react_result.hardcoded_urls)),
            parser_errors=fastapi_result.parser_errors + react_result.parser_errors,
            fastapi_facts=fastapi_result.fastapi_facts,
        )

    def _graph_assumptions(self, graph: nx.DiGraph, graph_result) -> list[str]:
        assumptions: list[str] = []
        if graph.number_of_nodes() == 0:
            assumptions.append("Service graph is empty because no analyzable repositories were detected.")
        if graph_result.unmatched_calls:
            assumptions.append(
                f"{len(graph_result.unmatched_calls)} frontend call(s) could not be mapped to backend endpoints."
            )
        return assumptions

    def _validate_data_flow(self, graph_result, runtime_result: RuntimeExecutionResult | None) -> list[dict]:
        if not runtime_result:
            return []

        probe_index: dict[tuple[str, str], Any] = {}
        for probe in runtime_result.probes:
            path = self._extract_path(probe.url)
            probe_index[(probe.method.upper(), path)] = probe

        issues: list[dict] = []

        for match in graph_result.matches:
            key = (match.call.method.upper(), match.endpoint.path)
            probe = probe_index.get(key)
            if probe is None:
                continue

            endpoint_ref = f"{match.endpoint.method} {match.endpoint.path}"
            if probe.error:
                issues.append(
                    {
                        "type": "data_flow_break",
                        "severity": "critical",
                        "service": match.backend_repo,
                        "endpoint": endpoint_ref,
                        "file": match.endpoint.file,
                        "line": match.endpoint.line,
                        "description": "Runtime probe failed while traversing expected data flow path.",
                        "evidence": {"error": probe.error, "url": probe.url},
                        "impact": "End-to-end propagation from frontend to backend is broken.",
                        "fix": "Repair service routing, startup health, or endpoint accessibility.",
                        "confidence": 0.9,
                    }
                )
                continue

            if probe.status_code is None:
                continue
            if probe.status_code >= 500:
                issues.append(
                    {
                        "type": "data_flow_break",
                        "severity": "critical",
                        "service": match.backend_repo,
                        "endpoint": endpoint_ref,
                        "file": match.endpoint.file,
                        "line": match.endpoint.line,
                        "description": "Backend returned server error during runtime data flow probe.",
                        "evidence": {
                            "status_code": probe.status_code,
                            "response": probe.response_body_snippet,
                        },
                        "impact": "Data propagation fails under runtime conditions.",
                        "fix": "Investigate backend exception path and dependency readiness.",
                        "confidence": 0.88,
                    }
                )
                continue

            if probe.status_code == 404:
                issues.append(
                    {
                        "type": "data_flow_break",
                        "severity": "critical",
                        "service": match.backend_repo,
                        "endpoint": endpoint_ref,
                        "file": match.endpoint.file,
                        "line": match.endpoint.line,
                        "description": "Runtime returned 404 for inferred integration endpoint.",
                        "evidence": {"status_code": 404, "url": probe.url},
                        "impact": "Flow path is misaligned between caller and callee services.",
                        "fix": "Align path prefixes/base URLs across frontend and backend services.",
                        "confidence": 0.86,
                    }
                )
                continue

            if 200 <= probe.status_code < 300 and match.endpoint.response_fields:
                missing_required = self._missing_required_response_fields(match.endpoint.response_fields, probe.response_body_snippet)
                if missing_required:
                    issues.append(
                        {
                            "type": "data_loss",
                            "severity": "high",
                            "service": match.backend_repo,
                            "endpoint": endpoint_ref,
                            "file": match.endpoint.file,
                            "line": match.endpoint.line,
                            "description": "Runtime response omits expected required fields from response schema.",
                            "evidence": {"missing_fields": missing_required, "status_code": probe.status_code},
                            "impact": "Downstream services or clients may receive incomplete data.",
                            "fix": "Preserve required response fields during transformation/serialization.",
                            "confidence": 0.75,
                        }
                    )

        return issues

    def _missing_required_response_fields(self, response_fields, body_snippet: str | None) -> list[str]:
        if not body_snippet:
            return []
        try:
            payload = json.loads(body_snippet)
        except json.JSONDecodeError:
            return []
        if not isinstance(payload, dict):
            return []

        missing: list[str] = []
        for field in response_fields:
            if field.required and field.name not in payload:
                missing.append(field.name)
        return missing

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

    def _merge_issues(
        self,
        agentic_issues: list,
        deterministic_issues: list,
    ) -> list:
        """Merge agentic LLM-generated issues with deterministic rule-engine issues.

        Agentic issues take priority for duplicates (better descriptions/fixes).
        Deterministic issues fill gaps to guarantee complete coverage."""
        merged: dict[tuple[str, str, str | None], Issue] = {}

        for issue in deterministic_issues:
            key = (issue.type, issue.service, issue.endpoint)
            if issue.source is None:
                issue = issue.model_copy(update={"source": "deterministic_rule_engine"})
            if not issue.provenance:
                issue = issue.model_copy(update={"provenance": self._default_provenance(issue)})
            merged[key] = issue

        agentic_count = 0
        for issue in agentic_issues:
            key = (issue.type, issue.service, issue.endpoint)
            if key in merged:
                agentic_count += 1
                existing = merged[key]
                merged[key] = issue.model_copy(update={
                    "provenance": sorted(set(existing.provenance + issue.provenance + self._default_provenance(existing) + self._default_provenance(issue))),
                })
                continue
            if not issue.provenance:
                issue = issue.model_copy(update={"provenance": self._default_provenance(issue)})
            merged[key] = issue

        logger.info(
            "merge_issues: deterministic_baseline=%d agentic_overlaps=%d agentic_unique=%d total=%d",
            len(deterministic_issues),
            agentic_count,
            len(agentic_issues) - agentic_count,
            len(merged),
        )
        return list(merged.values())

    def _finalize_issues(self, issues: list[Issue]) -> tuple[list[Issue], list[Issue]]:
        finalized: list[Issue] = []
        advisories: list[Issue] = []
        for issue in issues:
            enriched = self._enrich_issue(issue)
            if enriched.advisory:
                advisories.append(enriched)
            else:
                finalized.append(enriched)

        severity_order = {Severity.CRITICAL: 0, Severity.HIGH: 1, Severity.MEDIUM: 2}
        finalized.sort(key=lambda item: (severity_order[item.severity], -item.confidence, item.type, item.service))
        advisories.sort(key=lambda item: (severity_order[item.severity], -item.confidence, item.type, item.service))
        return finalized, advisories

    def _enrich_issue(self, issue: Issue) -> Issue:
        provenance = sorted(set(issue.provenance + self._default_provenance(issue)))
        band = self._confidence_band(issue, provenance)
        advisory = bool(issue.advisory)
        heuristic_only = issue.type in {
            "over_fetching",
            "missing_error_handling",
            "missing_error_handling_flow",
            "hardcoded_config",
        }
        if heuristic_only:
            advisory = True
        if issue.severity in {Severity.CRITICAL, Severity.HIGH} and band == ConfidenceBand.HEURISTIC:
            advisory = True
        if issue.type == "hardcoded_config" and issue.evidence.get("urls"):
            advisory = True

        return issue.model_copy(update={
            "provenance": provenance,
            "confidence_band": band,
            "advisory": advisory,
        })

    def _confidence_band(self, issue: Issue, provenance: list[str]) -> ConfidenceBand:
        deterministic_sources = {
            "mandatory_flow",
            "contract_validator",
            "graph_matcher",
            "deterministic_rule_engine",
            "standards_engine",
        }
        if any(source in provenance for source in deterministic_sources):
            return ConfidenceBand.DETERMINISTIC
        if len(set(provenance)) >= 2 or ("cross_reviewer" in provenance and issue.confidence >= 0.75):
            return ConfidenceBand.CORROBORATED
        return ConfidenceBand.HEURISTIC

    def _default_provenance(self, issue: Issue) -> list[str]:
        provenance: list[str] = []
        if issue.source:
            provenance.append(issue.source)
        if issue.source == "deterministic_rule_engine" or issue.source is None:
            provenance.append("deterministic_rule_engine")
            if issue.type in {
                "missing_auth",
                "missing_validation",
                "missing_authz_flow",
                "missing_ownership_check",
                "missing_rate_limit_flow",
                "missing_response_contract_flow",
                "missing_error_handling_flow",
                "missing_input_sanitization_flow",
                "missing_secret_pii_protection_flow",
                "missing_audit_trace_flow",
                "missing_idempotency_tx_flow",
            }:
                provenance.append("mandatory_flow")
            if issue.type in {
                "wrong_http_method",
                "missing_fields",
                "extra_fields",
                "type_mismatch",
                "missing_backend_schema",
                "response_field_missing",
                "response_field_not_consumed",
                "response_type_mismatch",
                "no_response_schema",
            }:
                provenance.append("contract_validator")
            if issue.type in {"broken_service_connection", "data_flow_break", "data_loss"}:
                provenance.append("graph_matcher")
        return provenance

    def _provenance_summary(self, issues: list[Issue], advisories: list[Issue]) -> dict[str, int]:
        counts: dict[str, int] = {}
        for issue in [*issues, *advisories]:
            for source in set(issue.provenance):
                counts[source] = counts.get(source, 0) + 1
        return dict(sorted(counts.items()))

    def _build_summary(self, issues) -> ReportSummary:
        critical = sum(1 for issue in issues if issue.severity.value == "critical")
        high = sum(1 for issue in issues if issue.severity.value == "high")
        medium = sum(1 for issue in issues if issue.severity.value == "medium")

        penalty = critical * 18 + high * 8 + medium * 3
        score = round(100 * 100 / (100 + penalty)) if penalty > 0 else 100
        return ReportSummary(score=score, critical=critical, high=high, medium=medium)

    def _residual_assumptions(
        self,
        repos,
        static_results: dict[str, StaticAnalysisResult],
        runtime_result: RuntimeExecutionResult | None,
    ) -> list[str]:
        assumptions: list[str] = []
        for repo in repos:
            static = static_results.get(repo.name)
            if static and static.parser_errors:
                assumptions.append(f"Parser recovered with errors for {repo.name}: {len(static.parser_errors)} file(s).")

        if runtime_result and runtime_result.errors:
            assumptions.append("Runtime validation completed with partial failures; static findings remain deterministic.")

        if any(repo.clone_error for repo in repos):
            assumptions.append("One or more repositories could not be cloned; report is partial for those services.")

        type_diag_statuses = Counter(item.status for item in getattr(self, "_last_type_diagnostics", []))
        if type_diag_statuses.get("tool_unavailable"):
            assumptions.append("One or more repositories skipped type diagnostics because the required toolchain was unavailable.")
        if type_diag_statuses.get("dependencies_missing"):
            assumptions.append("One or more repositories reported missing dependencies during type diagnostics; source-level type errors may be incomplete.")

        return assumptions

    async def _emit(
        self,
        callback: ProgressCallback | None,
        stage: str,
        message: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        if callback is None:
            return None

        event = {"stage": stage, "message": message}
        if payload:
            event["payload"] = payload

        result = callback(event)
        if inspect.isawaitable(result):
            logger.info("orchestrator emitting event stage=%s message=%s payload=%s", stage, message, payload)
            await result

    def _path(self, value: str) -> Path:
        return Path(value)

    def _write_final_trace(self, job_id: str | None, report: AnalysisReport) -> None:
        if not job_id or not settings.evidence_trace_enabled:
            return

        trace_dir = settings.evidence_trace_dir / job_id
        trace_dir.mkdir(parents=True, exist_ok=True)
        filepath = trace_dir / "08_final_report.json"
        payload = {
            "_meta": {
                "job_id": job_id,
                "node": "orchestrator_final_report",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            },
            "data": report.model_dump(mode="json"),
        }
        try:
            filepath.write_text(json.dumps(payload, indent=2, ensure_ascii=False), encoding="utf-8")
        except Exception:
            logger.exception("orchestrator final trace write failed job_id=%s", job_id)
