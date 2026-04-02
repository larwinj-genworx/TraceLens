from __future__ import annotations

import inspect
import json
from typing import Any, Awaitable, Callable

import networkx as nx

from src.analyzers.fastapi.parser import FastAPIParser
from src.analyzers.react.parser import ReactParser
from src.contracts.validator import ContractValidator
from src.flows.analyzer import MandatoryFlowAnalyzer
from src.llm.groq_client import GroqClient
from src.observability.logging.setup import get_logger
from src.rules.engine import RuleEngine
from src.runtime.orchestrator import RuntimeOrchestrator
from src.schemas.input import AnalysisRequest
from src.schemas.internal import AnalysisContext, RepoType, RuntimeExecutionResult, StaticAnalysisResult
from src.schemas.report import AnalysisReport, ReportSummary
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

    async def run(self, request: AnalysisRequest, progress_cb: ProgressCallback | None = None) -> AnalysisReport:
        assumptions: list[str] = []

        await self._emit(progress_cb, "repo_loading", "Loading and cloning repositories")
        repos, load_assumptions = self.repo_loader.load(list(request.repos))
        assumptions.extend(load_assumptions)

        static_results: dict[str, StaticAnalysisResult] = {}

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
                fastapi_result = self.fastapi_parser.parse(repo.name, repo_path=self._path(repo.local_path))
            if repo.repo_type in {RepoType.FRONTEND, RepoType.MIXED}:
                react_result = self.react_parser.parse(repo.name, repo_path=self._path(repo.local_path))

            static_results[repo.name] = self._merge_static_results(repo.name, fastapi_result, react_result)

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

        await self._emit(progress_cb, "mandatory_flow_index", "Building mandatory-flow coverage index")
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

        await self._emit(progress_cb, "rules", "Applying severity rule engine")
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
        )
        issues = self.rule_engine.evaluate(context)

        if request.enable_llm_enhancement:
            await self._emit(progress_cb, "llm", "Enhancing explanations and fixes via Groq")
            issues = await self.groq_client.enhance_issues(issues)

        await self._emit(progress_cb, "report", "Building final report")
        summary = self._build_summary(issues)

        assumptions.extend(self._residual_assumptions(repos, static_results, runtime_result))

        report = AnalysisReport(
            summary=summary,
            assumptions=sorted(set(assumptions)),
            issues=issues,
            flow_summary=mandatory_flow_result.flow_summary,
            flow_coverage=mandatory_flow_result.flow_coverage,
            observations=mandatory_flow_result.observations,
        )

        await self._emit(progress_cb, "complete", "Analysis completed", payload={"summary": summary.model_dump()})
        return report

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

    def _build_summary(self, issues) -> ReportSummary:
        critical = sum(1 for issue in issues if issue.severity.value == "critical")
        high = sum(1 for issue in issues if issue.severity.value == "high")
        medium = sum(1 for issue in issues if issue.severity.value == "medium")

        score = max(0, 100 - (critical * 18) - (high * 8) - (medium * 3))
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

        return assumptions

    async def _emit(
        self,
        callback: ProgressCallback | None,
        stage: str,
        message: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        if callback is None:
            return

        event = {"stage": stage, "message": message}
        if payload:
            event["payload"] = payload

        result = callback(event)
        if inspect.isawaitable(result):
            await result

    def _path(self, value: str):
        from pathlib import Path

        return Path(value)
