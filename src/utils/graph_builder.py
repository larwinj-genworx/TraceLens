from __future__ import annotations

import re
from urllib.parse import urlparse

import networkx as nx

from src.observability.logging.setup import get_logger
from src.schemas.internal import (
    EnvInferenceResult,
    FrontendCall,
    GraphBuildResult,
    RepoDescriptor,
    RepoType,
    ServiceMatch,
    StaticAnalysisResult,
)

logger = get_logger(__name__)


class ServiceGraphBuilder:
    def build(
        self,
        repos: list[RepoDescriptor],
        static_results: dict[str, StaticAnalysisResult],
        env_result: EnvInferenceResult,
    ) -> tuple[nx.DiGraph, GraphBuildResult]:
        graph = nx.DiGraph()
        matches: list[ServiceMatch] = []
        unmatched_calls: list[FrontendCall] = []
        edges: list[dict[str, str | float]] = []

        backend_repos = [repo for repo in repos if repo.repo_type in {RepoType.BACKEND, RepoType.MIXED} and not repo.clone_error]
        frontend_repos = [repo for repo in repos if repo.repo_type in {RepoType.FRONTEND, RepoType.MIXED} and not repo.clone_error]

        for repo in repos:
            graph.add_node(
                repo.name,
                repo_type=repo.repo_type.value,
                ports=repo.detected_ports,
                local_path=repo.local_path,
            )

        backend_endpoints_by_repo = {
            repo.name: static_results.get(repo.name, StaticAnalysisResult(repo=repo.name)).backend_endpoints
            for repo in backend_repos
        }

        for frontend in frontend_repos:
            frontend_result = static_results.get(frontend.name)
            if frontend_result is None:
                continue

            for call in frontend_result.frontend_calls:
                resolved_url = self._resolve_call_url(call, frontend.name, env_result)
                call_copy = call.model_copy(update={"resolved_url": resolved_url})
                candidate = self._best_match_for_call(call_copy, backend_repos, backend_endpoints_by_repo)
                if candidate is None:
                    unmatched_calls.append(call_copy)
                    continue

                matches.append(candidate)
                graph.add_edge(
                    candidate.frontend_repo,
                    candidate.backend_repo,
                    endpoint=candidate.endpoint.path,
                    method=candidate.call.method,
                    score=candidate.match_score,
                )
                edges.append(
                    {
                        "from": candidate.frontend_repo,
                        "to": candidate.backend_repo,
                        "endpoint": candidate.endpoint.path,
                        "method": candidate.call.method,
                        "score": round(candidate.match_score, 3),
                    }
                )

        return graph, GraphBuildResult(matches=matches, unmatched_calls=unmatched_calls, graph_edges=edges)

    def _resolve_call_url(self, call: FrontendCall, frontend_repo: str, env_result: EnvInferenceResult) -> str:
        raw = call.raw_url.strip()
        if not raw:
            return raw
        if raw.startswith("http://") or raw.startswith("https://"):
            return raw

        frontend_env = env_result.inferred_env.get(frontend_repo, {})
        base_url = ""

        if call.env_vars:
            for env_var in call.env_vars:
                if env_var in frontend_env:
                    base_url = frontend_env[env_var]
                    break

        if not base_url:
            for key, value in frontend_env.items():
                if any(marker in key.upper() for marker in ["API", "URL", "BASE"]):
                    base_url = value
                    break

        if raw.startswith("/"):
            return f"{base_url.rstrip('/')}{raw}" if base_url else raw
        if base_url:
            return f"{base_url.rstrip('/')}/{raw.lstrip('/')}"

        return raw

    def _best_match_for_call(
        self,
        call: FrontendCall,
        backend_repos: list[RepoDescriptor],
        backend_endpoints_by_repo: dict[str, list],
    ) -> ServiceMatch | None:
        best_match: ServiceMatch | None = None
        best_score = 0.0

        for backend in backend_repos:
            endpoints = backend_endpoints_by_repo.get(backend.name, [])
            for endpoint in endpoints:
                score = self._score_call_to_endpoint(call, endpoint, backend)
                if score > best_score:
                    best_score = score
                    best_match = ServiceMatch(
                        frontend_repo=call.service,
                        backend_repo=backend.name,
                        call=call,
                        endpoint=endpoint,
                        match_score=score,
                    )

        if best_match and best_score >= 0.55:
            return best_match
        return None

    def _score_call_to_endpoint(self, call: FrontendCall, endpoint, backend_repo: RepoDescriptor) -> float:
        score = 0.0

        resolved = call.resolved_url or call.raw_url
        parsed = urlparse(resolved) if resolved.startswith(("http://", "https://")) else None

        if parsed:
            host = (parsed.hostname or "").lower()
            if backend_repo.name.lower() in host:
                score += 0.45
            if parsed.port and parsed.port in backend_repo.detected_ports:
                score += 0.35
            path = parsed.path or "/"
        else:
            path = resolved if resolved.startswith("/") else f"/{resolved.lstrip('/')}"

        path_score = self._path_similarity(path, endpoint.path)
        score += 0.45 * path_score

        if call.method.upper() == endpoint.method.upper():
            score += 0.2

        return min(score, 1.0)

    def _path_similarity(self, source: str, target: str) -> float:
        src = self._normalize_path(source)
        tgt = self._normalize_path(target)

        if src == tgt:
            return 1.0
        if self._dynamic_path_match(src, tgt):
            return 0.9

        src_parts = [part for part in src.split("/") if part]
        tgt_parts = [part for part in tgt.split("/") if part]
        if not src_parts or not tgt_parts:
            return 0.0

        common = 0
        for left, right in zip(src_parts, tgt_parts, strict=False):
            if left == right:
                common += 1
            elif right.startswith("{") and right.endswith("}"):
                common += 1
            else:
                break

        return common / max(len(src_parts), len(tgt_parts))

    def _dynamic_path_match(self, source: str, target: str) -> bool:
        pattern = re.sub(r"\{[^/]+\}", r"[^/]+", target)
        pattern = f"^{pattern}$"
        return bool(re.match(pattern, source))

    def _normalize_path(self, path: str) -> str:
        normalized = re.sub(r"/{2,}", "/", path)
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        return normalized
