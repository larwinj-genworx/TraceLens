from __future__ import annotations

import hashlib
import json
import re
import shutil
import subprocess
from pathlib import Path

from src.config.settings import settings
from src.handlers.http_clients.github_client import GitHubClient
from src.observability.logging.setup import get_logger
from src.schemas.input import RepoInput
from src.schemas.internal import RepoDescriptor, RepoType

logger = get_logger(__name__)


IGNORED_DIRS = {
    ".git",
    "node_modules",
    "dist",
    "build",
    "venv",
    ".venv",
    "__pycache__",
    ".next",
    ".turbo",
    "coverage",
}

PORT_PATTERN = re.compile(r"(?:--port\s+|port\s*[=:]\s*|EXPOSE\s+)(\d{2,5})", re.IGNORECASE)


class RepoLoader:
    def __init__(self, workspace_root: Path | None = None) -> None:
        self.workspace_root = workspace_root or settings.analysis_workspace
        self.workspace_root.mkdir(parents=True, exist_ok=True)

    def load_from_paths(self, dirs: list[Path], names: list[str] | None = None) -> tuple[list[RepoDescriptor], list[str]]:
        """Load repos from pre-extracted local directories (for ZIP uploads).
        Skips git clone and runs type/port detection directly."""
        assumptions: list[str] = []
        descriptors: list[RepoDescriptor] = []

        for idx, target_dir in enumerate(dirs):
            repo_name = names[idx] if names and idx < len(names) else target_dir.name
            if not target_dir.exists():
                assumptions.append(f"Directory not found for {repo_name}: {target_dir}. Skipping.")
                descriptors.append(
                    RepoDescriptor(
                        name=repo_name,
                        url=f"zip://{repo_name}",
                        local_path=str(target_dir),
                        repo_type=RepoType.UNKNOWN,
                        clone_error="directory_not_found",
                    )
                )
                continue

            repo_type = self._detect_repo_type(target_dir)
            ports = self._detect_ports(target_dir, repo_type)
            fastapi_entrypoint = self._detect_fastapi_entrypoint(target_dir)
            frontend_start_script = self._detect_frontend_start_script(target_dir)

            if not ports:
                inferred_default = 8000 if repo_type in {RepoType.BACKEND, RepoType.MIXED} else 3000
                ports = [inferred_default]
                assumptions.append(
                    f"No explicit port found for {repo_name}; defaulted to {inferred_default} based on repo type {repo_type.value}."
                )

            descriptors.append(
                RepoDescriptor(
                    name=repo_name,
                    url=f"zip://{repo_name}",
                    local_path=str(target_dir),
                    repo_type=repo_type,
                    detected_ports=sorted(set(ports)),
                    fastapi_entrypoint=fastapi_entrypoint,
                    frontend_start_script=frontend_start_script,
                )
            )

        return descriptors, assumptions

    def load(self, repos: list[RepoInput | str]) -> tuple[list[RepoDescriptor], list[str]]:
        assumptions: list[str] = []
        descriptors: list[RepoDescriptor] = []

        for entry in repos:
            if isinstance(entry, RepoInput):
                url = entry.url
                branch = entry.branch
                source_type = getattr(entry, "source_type", "git")
                local_path = getattr(entry, "local_path", None)
            else:
                url = str(entry)
                branch = None
                source_type = "git"
                local_path = None

            if source_type == "zip" and local_path:
                zip_dirs = [Path(local_path)]
                zip_names = [Path(local_path).name]
                zip_descs, zip_assumptions = self.load_from_paths(zip_dirs, zip_names)
                descriptors.extend(zip_descs)
                assumptions.extend(zip_assumptions)
                continue

            repo_name = GitHubClient.extract_repo_name(url)
            cache_key = f"{url}#{branch or ''}"
            unique_suffix = hashlib.sha1(cache_key.encode("utf-8")).hexdigest()[:8]
            target_dir = self.workspace_root / f"{repo_name}-{unique_suffix}"

            if target_dir.exists():
                shutil.rmtree(target_dir)

            normalized_url = GitHubClient.normalize_repo_url(url)
            clone_result = self._clone_repo(normalized_url, target_dir, branch=branch)
            if clone_result is not None:
                assumptions.append(f"Clone failed for {url}: {clone_result}. Continuing with partial analysis.")
                descriptors.append(
                    RepoDescriptor(
                        name=repo_name,
                        url=url,
                        local_path=str(target_dir),
                        repo_type=RepoType.UNKNOWN,
                        clone_error=clone_result,
                    )
                )
                continue

            repo_type = self._detect_repo_type(target_dir)
            ports = self._detect_ports(target_dir, repo_type)
            fastapi_entrypoint = self._detect_fastapi_entrypoint(target_dir)
            frontend_start_script = self._detect_frontend_start_script(target_dir)

            if not ports:
                inferred_default = 8000 if repo_type in {RepoType.BACKEND, RepoType.MIXED} else 3000
                ports = [inferred_default]
                assumptions.append(
                    f"No explicit port found for {repo_name}; defaulted to {inferred_default} based on repo type {repo_type.value}."
                )

            descriptors.append(
                RepoDescriptor(
                    name=repo_name,
                    url=url,
                    local_path=str(target_dir),
                    repo_type=repo_type,
                    detected_ports=sorted(set(ports)),
                    fastapi_entrypoint=fastapi_entrypoint,
                    frontend_start_script=frontend_start_script,
                )
            )

        return descriptors, assumptions

    def _clone_repo(self, url: str, target_dir: Path, *, branch: str | None = None) -> str | None:
        cmd = [
            "git",
            "clone",
            "--depth",
            str(settings.git_clone_depth),
        ]
        if branch:
            cmd += ["--branch", branch]
        cmd += [url, str(target_dir)]
        try:
            subprocess.run(
                cmd,
                check=True,
                capture_output=True,
                text=True,
                timeout=180,
            )
            return None
        except subprocess.TimeoutExpired:
            return "git clone timed out"
        except subprocess.CalledProcessError as exc:
            stderr = (exc.stderr or "").strip() or "git clone failed"
            return stderr[:300]

    def _detect_repo_type(self, repo_path: Path) -> RepoType:
        has_react = self._has_react(repo_path)
        has_fastapi = self._has_fastapi(repo_path)
        if has_react and has_fastapi:
            return RepoType.MIXED
        if has_react:
            return RepoType.FRONTEND
        if has_fastapi:
            return RepoType.BACKEND
        return RepoType.UNKNOWN

    def _has_react(self, repo_path: Path) -> bool:
        package_json = repo_path / "package.json"
        if not package_json.exists():
            return False
        try:
            payload = json.loads(package_json.read_text(encoding="utf-8", errors="ignore"))
        except json.JSONDecodeError:
            return False
        deps = {**payload.get("dependencies", {}), **payload.get("devDependencies", {})}
        return any(key.lower() == "react" for key in deps.keys())

    def _has_fastapi(self, repo_path: Path) -> bool:
        requirements = list(repo_path.glob("requirements*.txt"))
        for req_file in requirements:
            if "fastapi" in req_file.read_text(encoding="utf-8", errors="ignore").lower():
                return True
        for py_file in self._iter_files(repo_path, suffixes={".py"}):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            if "FastAPI(" in content or "from fastapi" in content:
                return True
        return False

    def _detect_ports(self, repo_path: Path, repo_type: RepoType) -> list[int]:
        ports: list[int] = []

        dockerfile = repo_path / "Dockerfile"
        if dockerfile.exists():
            for match in PORT_PATTERN.findall(dockerfile.read_text(encoding="utf-8", errors="ignore")):
                ports.append(int(match))

        package_json = repo_path / "package.json"
        if package_json.exists():
            try:
                payload = json.loads(package_json.read_text(encoding="utf-8", errors="ignore"))
                scripts = payload.get("scripts", {})
                for script in scripts.values():
                    for match in PORT_PATTERN.findall(script):
                        ports.append(int(match))
            except json.JSONDecodeError:
                pass

        for file_path in self._iter_files(repo_path, suffixes={".py", ".js", ".ts", ".example"}):
            if file_path.suffix == ".example" and not file_path.name.endswith(".env.example"):
                continue
            content = file_path.read_text(encoding="utf-8", errors="ignore")
            for match in PORT_PATTERN.findall(content):
                candidate = int(match)
                if 1 <= candidate <= 65535:
                    ports.append(candidate)

        if repo_type in {RepoType.BACKEND, RepoType.MIXED} and 8000 not in ports:
            ports.append(8000)
        if repo_type == RepoType.FRONTEND and 3000 not in ports and 5173 not in ports:
            ports.append(3000)

        return sorted(set(ports))

    def _detect_fastapi_entrypoint(self, repo_path: Path) -> str | None:
        for py_file in self._iter_files(repo_path, suffixes={".py"}):
            content = py_file.read_text(encoding="utf-8", errors="ignore")
            if "FastAPI(" not in content:
                continue
            rel = py_file.relative_to(repo_path).with_suffix("")
            return ".".join(rel.parts)
        return None

    def _detect_frontend_start_script(self, repo_path: Path) -> str | None:
        package_json = repo_path / "package.json"
        if not package_json.exists():
            return None
        try:
            payload = json.loads(package_json.read_text(encoding="utf-8", errors="ignore"))
            scripts = payload.get("scripts", {})
        except json.JSONDecodeError:
            return None

        for key in ("start", "dev", "serve"):
            if key in scripts:
                return key
        return None

    def _iter_files(self, root: Path, suffixes: set[str]) -> list[Path]:
        files: list[Path] = []
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in suffixes:
                continue
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            files.append(path)
        return files
