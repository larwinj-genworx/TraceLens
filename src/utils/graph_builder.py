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

    # Minimum path similarity required before any host/port/method bonuses are
    # applied.  Prevents a port-match bonus from rescuing a near-zero path score
    # (e.g. /auth/register-org vs /api/logs sharing only the leading "api" segment).
    _MIN_PATH_SCORE: float = 0.40

    def _score_call_to_endpoint(self, call: FrontendCall, endpoint, backend_repo: RepoDescriptor) -> float:
        resolved = call.resolved_url or call.raw_url
        parsed = urlparse(resolved) if resolved.startswith(("http://", "https://")) else None

        if parsed:
            path = parsed.path or "/"
        else:
            path = resolved if resolved.startswith("/") else f"/{resolved.lstrip('/')}"

        path_score = self._path_similarity(path, endpoint.path)

        # Hard gate: discard the candidate immediately if path similarity is too
        # weak regardless of how well host/port/method align.
        if path_score < self._MIN_PATH_SCORE:
            return 0.0

        score = 0.45 * path_score

        if parsed:
            host = (parsed.hostname or "").lower()
            if backend_repo.name.lower() in host:
                # Host name match is a strong signal – keep a high bonus but
                # only when the path gate has already passed.
                score += 0.40
            elif parsed.port and parsed.port in backend_repo.detected_ports:
                # Port match is weaker: many services share the same dev port.
                # Reduce from 0.35 → 0.20 so it cannot rescue a marginal path.
                score += 0.20

        if call.method.upper() == endpoint.method.upper():
            score += 0.20

        return min(score, 1.0)

    def _path_similarity(self, source: str, target: str) -> float:
        """
        Score how closely a frontend URL path matches a backend endpoint path.

        Strategy (highest to lowest):
        1. Exact match after normalization → 1.0
        2. Dynamic path match (backend ``{param}`` as regex wildcard) → 0.9
        3. Suffix-based match: does *target* appear as a suffix of *source*?
           This handles the common case where the frontend URL includes a version
           prefix (``/api/v1``) that is absent from the stored backend path.
        4. Segment-level scoring across all positions without early break — a
           strict break at the first non-matching segment misses routes whose
           only difference is a leading version/api prefix.
        """
        src = self._normalize_path(source)
        tgt = self._normalize_path(target)

        if src == tgt:
            return 1.0
        if self._dynamic_path_match(src, tgt):
            return 0.9

        src_parts = [p for p in src.split("/") if p]
        tgt_parts = [p for p in tgt.split("/") if p]
        if not src_parts or not tgt_parts:
            return 0.0

        suffix_score = self._suffix_segment_score(src_parts, tgt_parts)
        segment_score = self._full_segment_score(src_parts, tgt_parts)
        return max(suffix_score, segment_score)

    def _suffix_segment_score(self, src_parts: list[str], tgt_parts: list[str]) -> float:
        """
        Check whether *tgt_parts* matches the tail of *src_parts* segment-by-segment.

        A perfect suffix match (all target segments align with the last N source
        segments) scores highly, with a small penalty proportional to how many
        extra prefix segments the source has.  This handles ``/api/v1/users/{id}``
        (frontend) vs ``/users/{id}`` (backend).
        """
        tgt_len = len(tgt_parts)
        src_len = len(src_parts)

        if tgt_len > src_len:
            # Symmetry: if target is longer try reversed direction with penalty
            score = self._suffix_segment_score(tgt_parts, src_parts)
            return score * 0.85

        # Align tgt against the last tgt_len segments of src
        src_tail = src_parts[src_len - tgt_len:]
        matched = sum(1 for s, t in zip(src_tail, tgt_parts) if self._segments_match(s, t))

        if matched == tgt_len:
            # All target segments matched – penalise lightly for extra source prefix
            extra = src_len - tgt_len
            if extra == 0:
                return 1.0
            if extra == 1:
                return 0.92
            if extra == 2:
                return 0.84
            return 0.76

        # Partial suffix match
        return matched / max(src_len, tgt_len)

    def _full_segment_score(self, src_parts: list[str], tgt_parts: list[str]) -> float:
        """
        Score the overall segment alignment without breaking at the first mismatch.

        The original algorithm broke on the first non-matching segment which made
        paths that differ only in a leading prefix score zero.  Counting all
        aligned matches gives a fairer signal.
        """
        matched = sum(
            1 for s, t in zip(src_parts, tgt_parts) if self._segments_match(s, t)
        )
        return matched / max(len(src_parts), len(tgt_parts))

    @staticmethod
    def _segments_match(src: str, tgt: str) -> bool:
        """
        Return True if a source path segment and a target path segment are
        considered equivalent for matching purposes.

        Rules:
        - Exact string equality always matches.
        - A backend path parameter ``{id}`` matches any frontend segment,
          whether it is a concrete runtime value or a template expression.
        - Frontend path parameters can be expressed in several forms:
          - RFC-style ``{userId}`` (sometimes used in typed routes/mocks)
          - JavaScript template literal ``${userId}`` or ``${user.id}``
          - React-Router / path-to-regexp ``:userId`` parameters
          All of these are treated as parameter placeholders that match any
          backend path parameter without matching a concrete backend word.
        """
        if src == tgt:
            return True

        tgt_is_param = tgt.startswith("{") and tgt.endswith("}")

        # Recognise all common frontend "dynamic segment" styles
        src_is_param = (
            (src.startswith("{") and src.endswith("}"))   # {id}
            or (src.startswith("${") and src.endswith("}"))  # ${id}  JS template literal
            or (src.startswith(":") and len(src) > 1)         # :id   path-to-regexp
        )

        if tgt_is_param:
            # Backend param accepts any concrete value or frontend template expression
            return True
        if src_is_param and not tgt_is_param:
            # Frontend param should NOT map to a concrete backend word segment
            return False
        return False

    def _dynamic_path_match(self, source: str, target: str) -> bool:
        pattern = re.sub(r"\{[^/]+\}", r"[^/]+", target)
        pattern = f"^{pattern}$"
        return bool(re.match(pattern, source))

    def _normalize_path(self, path: str) -> str:
        normalized = re.sub(r"/{2,}", "/", path)
        if not normalized.startswith("/"):
            normalized = f"/{normalized}"
        return normalized
