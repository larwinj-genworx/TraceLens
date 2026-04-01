from __future__ import annotations

import re
from pathlib import Path

from src.observability.logging.setup import get_logger
from src.schemas.internal import EnvInferenceResult, RepoDescriptor, RepoType, StaticAnalysisResult

logger = get_logger(__name__)

IGNORED_DIRS = {".git", "node_modules", "dist", "build", ".next", ".venv", "venv", "__pycache__"}
ENV_JS_PATTERN = re.compile(r"(?:process\.env|import\.meta\.env)\.([A-Z0-9_]+)")
ENV_PY_PATTERN = re.compile(r"os\.(?:getenv|environ\.get)\(\s*['\"]([A-Z0-9_]+)['\"]")
ENV_PY_PATTERN_ALT = re.compile(r"os\.environ\[['\"]([A-Z0-9_]+)['\"]\]")
URL_PATTERN = re.compile(r"https?://[^'\"\s)]+")


class EnvInferenceEngine:
    def infer(
        self,
        repos: list[RepoDescriptor],
        static_results: dict[str, StaticAnalysisResult],
    ) -> EnvInferenceResult:
        assumptions: list[str] = []
        inferred_env: dict[str, dict[str, str]] = {}
        service_base_urls: dict[str, str] = {}

        backend_repos = [repo for repo in repos if repo.repo_type in {RepoType.BACKEND, RepoType.MIXED} and not repo.clone_error]

        for backend in backend_repos:
            port = backend.detected_ports[0] if backend.detected_ports else 8000
            service_base_urls[backend.name] = f"http://{backend.name}:{port}"

        discovered_repo_env_vars: dict[str, set[str]] = {}
        discovered_urls: dict[str, set[str]] = {}

        for repo in repos:
            static = static_results.get(repo.name)
            vars_found: set[str] = set(static.env_references if static else [])
            urls_found: set[str] = set(static.hardcoded_urls if static else [])
            scanned_vars, scanned_urls = self._scan_repo_source(Path(repo.local_path))
            vars_found.update(scanned_vars)
            urls_found.update(scanned_urls)
            discovered_repo_env_vars[repo.name] = vars_found
            discovered_urls[repo.name] = urls_found

        for repo in repos:
            repo_env: dict[str, str] = {}
            vars_found = discovered_repo_env_vars.get(repo.name, set())

            if repo.repo_type in {RepoType.FRONTEND, RepoType.MIXED}:
                inferred_api_url, assumption = self._infer_frontend_api_url(repo, backend_repos, vars_found)
                if inferred_api_url:
                    for key in vars_found:
                        if self._looks_like_api_url_var(key):
                            repo_env[key] = inferred_api_url
                    if not any(self._looks_like_api_url_var(k) for k in vars_found):
                        repo_env["VITE_API_BASE_URL"] = inferred_api_url
                        repo_env["REACT_APP_API_BASE_URL"] = inferred_api_url
                        assumptions.append(
                            f"No explicit frontend API env var found in {repo.name}; injected VITE_API_BASE_URL/REACT_APP_API_BASE_URL."
                        )
                if assumption:
                    assumptions.append(assumption)

            if repo.repo_type in {RepoType.BACKEND, RepoType.MIXED}:
                default_port = repo.detected_ports[0] if repo.detected_ports else 8000
                repo_env.setdefault("PORT", str(default_port))
                for key in vars_found:
                    if key == "PORT":
                        continue
                    inferred_value, value_assumption = self._infer_backend_env_value(key, repo, backend_repos)
                    if inferred_value:
                        repo_env[key] = inferred_value
                        if value_assumption:
                            assumptions.append(value_assumption)

            if repo.repo_type == RepoType.UNKNOWN:
                if vars_found:
                    assumptions.append(
                        f"Repository {repo.name} type is unknown; skipped targeted env inference for vars: {sorted(vars_found)}."
                    )

            inferred_env[repo.name] = repo_env

        for repo in repos:
            if repo.repo_type in {RepoType.FRONTEND, RepoType.MIXED}:
                if not discovered_repo_env_vars.get(repo.name):
                    urls = sorted(discovered_urls.get(repo.name, set()))
                    if urls:
                        assumptions.append(
                            f"{repo.name} had no env references; observed hardcoded URLs and used route matching fallback."
                        )

        return EnvInferenceResult(
            inferred_env=inferred_env,
            assumptions=assumptions,
            service_base_urls=service_base_urls,
        )

    def _infer_frontend_api_url(
        self,
        frontend_repo: RepoDescriptor,
        backend_repos: list[RepoDescriptor],
        env_vars: set[str],
    ) -> tuple[str | None, str | None]:
        if not backend_repos:
            return None, f"No backend repos detected for {frontend_repo.name}; frontend API URL inference skipped."

        if len(backend_repos) == 1:
            backend = backend_repos[0]
            port = backend.detected_ports[0] if backend.detected_ports else 8000
            return (
                f"http://{backend.name}:{port}",
                f"Single backend detected ({backend.name}); mapped frontend {frontend_repo.name} API envs to {backend.name}:{port}.",
            )

        frontend_tokens = self._tokenize(frontend_repo.name)
        candidate_vars = [var for var in env_vars if self._looks_like_api_url_var(var)]

        best_backend: RepoDescriptor | None = None
        best_score = -1
        for backend in backend_repos:
            score = 0
            backend_tokens = self._tokenize(backend.name)
            score += len(frontend_tokens.intersection(backend_tokens)) * 2
            for var in candidate_vars:
                var_tokens = self._tokenize(var)
                score += len(var_tokens.intersection(backend_tokens)) * 3
            if score > best_score:
                best_backend = backend
                best_score = score

        if best_backend is None:
            fallback = backend_repos[0]
            port = fallback.detected_ports[0] if fallback.detected_ports else 8000
            return (
                f"http://{fallback.name}:{port}",
                f"Ambiguous backend mapping for {frontend_repo.name}; defaulted API URL to {fallback.name}:{port}.",
            )

        port = best_backend.detected_ports[0] if best_backend.detected_ports else 8000
        return f"http://{best_backend.name}:{port}", None

    def _infer_backend_env_value(
        self,
        key: str,
        repo: RepoDescriptor,
        backend_repos: list[RepoDescriptor],
    ) -> tuple[str | None, str | None]:
        upper_key = key.upper()
        if "PORT" in upper_key:
            port = repo.detected_ports[0] if repo.detected_ports else 8000
            return str(port), None
        if any(marker in upper_key for marker in ["DB", "DATABASE"]):
            return f"sqlite:////tmp/{repo.name}.db", f"Inferred local sqlite database URL for {repo.name}:{key}."
        if any(marker in upper_key for marker in ["REDIS", "CACHE"]):
            return "redis://localhost:6379/0", f"Inferred default Redis URL for {repo.name}:{key}."
        if any(marker in upper_key for marker in ["SECRET", "TOKEN", "KEY", "PASSWORD"]):
            return "inferred-development-secret", f"Injected deterministic development secret for {repo.name}:{key}."
        if any(marker in upper_key for marker in ["API", "SERVICE", "BASE_URL", "URL"]):
            mapped = self._map_to_backend_service_url(key, repo, backend_repos)
            if mapped:
                return mapped, f"Mapped {repo.name}:{key} to inferred backend service URL {mapped}."
        return None, None

    def _map_to_backend_service_url(
        self,
        key: str,
        current_repo: RepoDescriptor,
        backend_repos: list[RepoDescriptor],
    ) -> str | None:
        key_tokens = self._tokenize(key)
        best_repo: RepoDescriptor | None = None
        best_score = 0

        for backend in backend_repos:
            if backend.name == current_repo.name:
                continue
            score = len(key_tokens.intersection(self._tokenize(backend.name)))
            if score > best_score:
                best_score = score
                best_repo = backend

        if best_repo is None and backend_repos:
            candidates = [repo for repo in backend_repos if repo.name != current_repo.name]
            best_repo = candidates[0] if candidates else None

        if best_repo is None:
            return None

        port = best_repo.detected_ports[0] if best_repo.detected_ports else 8000
        return f"http://{best_repo.name}:{port}"

    def _scan_repo_source(self, repo_path: Path) -> tuple[set[str], set[str]]:
        env_vars: set[str] = set()
        urls: set[str] = set()
        if not repo_path.exists():
            return env_vars, urls

        for path in repo_path.rglob("*"):
            if not path.is_file() or path.suffix.lower() not in {
                ".py",
                ".js",
                ".jsx",
                ".ts",
                ".tsx",
                ".mjs",
                ".cjs",
                ".json",
                ".yaml",
                ".yml",
                ".example",
            }:
                continue
            if path.suffix.lower() == ".example" and not path.name.endswith(".env.example"):
                continue
            if any(part in IGNORED_DIRS for part in path.parts):
                continue

            content = path.read_text(encoding="utf-8", errors="ignore")
            env_vars.update(ENV_JS_PATTERN.findall(content))
            env_vars.update(ENV_PY_PATTERN.findall(content))
            env_vars.update(ENV_PY_PATTERN_ALT.findall(content))
            urls.update(URL_PATTERN.findall(content))

        return env_vars, urls

    def _looks_like_api_url_var(self, env_key: str) -> bool:
        key = env_key.upper()
        markers = ["API", "BASE_URL", "BACKEND", "SERVICE", "URL"]
        return any(marker in key for marker in markers)

    def _tokenize(self, value: str) -> set[str]:
        return {token for token in re.split(r"[^a-zA-Z0-9]+", value.lower()) if token}
