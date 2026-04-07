from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Iterable

from src.config.settings import settings
from src.observability.logging.setup import get_logger
from src.schemas.internal import RepoDescriptor, RepoType, TypeDiagnostic

logger = get_logger(__name__)

_IGNORED_DIRS = {".git", "node_modules", "dist", "build", ".next", "coverage", "__pycache__", ".venv", "venv"}
_TS_MISSING_PATTERNS = ("Cannot find module", "Cannot find type definition file")
_PY_MISSING_RULES = {"reportMissingImports", "reportMissingModuleSource"}


class TypeDiagnosticsRunner:
    def __init__(self, timeout_seconds: int | None = None) -> None:
        self.timeout_seconds = timeout_seconds or min(settings.request_timeout_seconds, 60)

    def run(self, repos: list[RepoDescriptor]) -> list[TypeDiagnostic]:
        diagnostics: list[TypeDiagnostic] = []
        for repo in repos:
            if repo.clone_error:
                diagnostics.append(
                    TypeDiagnostic(
                        repo=repo.name,
                        tool="typecheck",
                        status="skipped",
                        message=f"Repository unavailable for type diagnostics: {repo.clone_error}",
                    )
                )
                continue

            repo_path = Path(repo.local_path)
            if repo.repo_type in {RepoType.FRONTEND, RepoType.MIXED}:
                diagnostics.extend(self._run_typescript(repo.name, repo_path))
            if repo.repo_type in {RepoType.BACKEND, RepoType.MIXED}:
                diagnostics.extend(self._run_python(repo.name, repo_path))
        return diagnostics

    def _run_typescript(self, repo: str, repo_path: Path) -> list[TypeDiagnostic]:
        ts_files = list(self._iter_files(repo_path, {".ts", ".tsx"}))
        if not ts_files:
            return []

        tsconfig = self._find_first(repo_path, ("tsconfig.json", "tsconfig.app.json", "tsconfig.base.json"))
        if tsconfig is None:
            return [
                TypeDiagnostic(
                    repo=repo,
                    tool="tsc",
                    status="config_missing",
                    message="TypeScript sources detected but no tsconfig was found.",
                )
            ]

        local_tsc = repo_path / "node_modules" / ".bin" / "tsc"
        tsc = str(local_tsc) if local_tsc.exists() else shutil.which("tsc")
        if not tsc:
            return [
                TypeDiagnostic(
                    repo=repo,
                    tool="tsc",
                    status="tool_unavailable",
                    message="TypeScript compiler is not available in PATH or local node_modules/.bin.",
                )
            ]

        result = self._run_command([tsc, "-p", str(tsconfig), "--noEmit", "--pretty", "false"], repo_path)
        if result.returncode == 0:
            return []

        output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
        if self._is_ts_dependency_failure(repo_path, output):
            return [
                TypeDiagnostic(
                    repo=repo,
                    tool="tsc",
                    status="dependencies_missing",
                    message="TypeScript check could not resolve project dependencies.",
                )
            ]

        parsed = self._parse_tsc_output(repo, output, repo_path)
        if parsed:
            return parsed
        return [
            TypeDiagnostic(
                repo=repo,
                tool="tsc",
                status="error",
                message=output.splitlines()[0] if output else "TypeScript check failed.",
            )
        ]

    def _run_python(self, repo: str, repo_path: Path) -> list[TypeDiagnostic]:
        py_files = list(self._iter_files(repo_path, {".py"}))
        if not py_files:
            return []

        pyright = shutil.which("pyright")
        if pyright:
            result = self._run_command([pyright, str(repo_path), "--outputjson"], repo_path)
            parsed = self._parse_pyright_output(repo, result.stdout or result.stderr, repo_path)
            if result.returncode == 0 and not parsed:
                return []
            if parsed and self._is_python_dependency_failure(parsed):
                return [
                    TypeDiagnostic(
                        repo=repo,
                        tool="pyright",
                        status="dependencies_missing",
                        message="Pyright could not resolve one or more project imports.",
                    )
                ]
            if parsed:
                return parsed
            return [
                TypeDiagnostic(
                    repo=repo,
                    tool="pyright",
                    status="error",
                    message=(result.stdout or result.stderr or "Pyright failed.").splitlines()[0],
                )
            ]

        mypy = shutil.which("mypy")
        if not mypy:
            return [
                TypeDiagnostic(
                    repo=repo,
                    tool="python-typecheck",
                    status="tool_unavailable",
                    message="Neither pyright nor mypy is available for Python type diagnostics.",
                )
            ]

        config = self._find_first(repo_path, ("pyproject.toml", "mypy.ini", ".mypy.ini", "setup.cfg"))
        if config is None:
            return [
                TypeDiagnostic(
                    repo=repo,
                    tool="mypy",
                    status="config_missing",
                    message="Python sources detected but no mypy/pyproject config was found.",
                )
            ]

        result = self._run_command(
            [mypy, str(repo_path), "--show-error-codes", "--no-error-summary", "--hide-error-context", "--config-file", str(config)],
            repo_path,
        )
        if result.returncode == 0:
            return []
        output = "\n".join(part for part in (result.stdout, result.stderr) if part).strip()
        if self._looks_like_python_dependency_failure(output):
            return [
                TypeDiagnostic(
                    repo=repo,
                    tool="mypy",
                    status="dependencies_missing",
                    message="Mypy could not resolve one or more project imports.",
                )
            ]
        parsed = self._parse_mypy_output(repo, output, repo_path)
        if parsed:
            return parsed
        return [
            TypeDiagnostic(
                repo=repo,
                tool="mypy",
                status="error",
                message=output.splitlines()[0] if output else "Mypy failed.",
            )
        ]

    def _run_command(self, cmd: list[str], cwd: Path) -> subprocess.CompletedProcess[str]:
        logger.info("typecheck command repo=%s cmd=%s", cwd, cmd)
        try:
            return subprocess.run(
                cmd,
                cwd=cwd,
                capture_output=True,
                text=True,
                timeout=self.timeout_seconds,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return subprocess.CompletedProcess(cmd, 124, stdout="", stderr="Typecheck command timed out.")
        except OSError as exc:
            return subprocess.CompletedProcess(cmd, 127, stdout="", stderr=str(exc))

    def _parse_tsc_output(self, repo: str, output: str, repo_path: Path) -> list[TypeDiagnostic]:
        diagnostics: list[TypeDiagnostic] = []
        for line in output.splitlines():
            match = line.strip()
            parsed = self._parse_tsc_line(match)
            if parsed is None:
                continue
            file_path, line_no, code, message = parsed
            diagnostics.append(
                TypeDiagnostic(
                    repo=repo,
                    tool="tsc",
                    status="error",
                    file=self._relativize(file_path, repo_path),
                    line=line_no,
                    code=code,
                    message=message,
                )
            )
        return diagnostics[:20]

    def _parse_pyright_output(self, repo: str, output: str, repo_path: Path) -> list[TypeDiagnostic]:
        try:
            payload = json.loads(output)
        except json.JSONDecodeError:
            return []

        diagnostics: list[TypeDiagnostic] = []
        for item in payload.get("generalDiagnostics", [])[:20]:
            file_path = item.get("file")
            range_start = item.get("range", {}).get("start", {})
            rule = item.get("rule")
            diagnostics.append(
                TypeDiagnostic(
                    repo=repo,
                    tool="pyright",
                    status="error",
                    file=self._relativize(file_path, repo_path) if file_path else None,
                    line=(range_start.get("line", 0) + 1) if isinstance(range_start.get("line"), int) else None,
                    code=str(rule) if rule else None,
                    message=str(item.get("message", "Pyright error")),
                )
            )
        return diagnostics

    def _parse_mypy_output(self, repo: str, output: str, repo_path: Path) -> list[TypeDiagnostic]:
        diagnostics: list[TypeDiagnostic] = []
        for line in output.splitlines():
            parts = line.split(":", 3)
            if len(parts) < 4:
                continue
            file_path, line_no, level, rest = parts
            if "error" not in level:
                continue
            code = None
            message = rest.strip()
            if message.endswith("]") and "[" in message:
                message, code = message.rsplit("[", 1)
                message = message.strip()
                code = code.rstrip("]").strip()
            diagnostics.append(
                TypeDiagnostic(
                    repo=repo,
                    tool="mypy",
                    status="error",
                    file=self._relativize(file_path, repo_path),
                    line=int(line_no) if line_no.isdigit() else None,
                    code=code,
                    message=message,
                )
            )
        return diagnostics[:20]

    def _parse_tsc_line(self, line: str) -> tuple[str, int | None, str | None, str] | None:
        import re

        match = re.match(r"^(?P<file>.+?)\((?P<line>\d+),(?P<col>\d+)\): error (?P<code>TS\d+): (?P<msg>.+)$", line)
        if not match:
            return None
        return (
            match.group("file"),
            int(match.group("line")),
            match.group("code"),
            match.group("msg").strip(),
        )

    def _is_ts_dependency_failure(self, repo_path: Path, output: str) -> bool:
        has_node_modules = (repo_path / "node_modules").exists()
        missing_refs = any(pattern in output for pattern in _TS_MISSING_PATTERNS)
        return missing_refs and not has_node_modules

    def _is_python_dependency_failure(self, diagnostics: list[TypeDiagnostic]) -> bool:
        if not diagnostics:
            return False
        missing = [diag for diag in diagnostics if (diag.code or "") in _PY_MISSING_RULES]
        return len(missing) == len(diagnostics)

    def _looks_like_python_dependency_failure(self, output: str) -> bool:
        lowered = output.lower()
        return "cannot find implementation or library stub" in lowered or "cannot find module named" in lowered

    def _find_first(self, repo_path: Path, candidates: tuple[str, ...]) -> Path | None:
        for name in candidates:
            candidate = repo_path / name
            if candidate.exists():
                return candidate
        for name in candidates:
            matches = sorted(
                path for path in repo_path.rglob(name)
                if not self._is_ignored(path)
            )
            if matches:
                return matches[0]
        return None

    def _iter_files(self, root: Path, suffixes: set[str]) -> Iterable[Path]:
        for path in root.rglob("*"):
            if not path.is_file() or path.suffix not in suffixes:
                continue
            if self._is_ignored(path):
                continue
            yield path

    def _is_ignored(self, path: Path) -> bool:
        return any(part in _IGNORED_DIRS for part in path.parts)

    def _relativize(self, file_path: str | Path, repo_path: Path) -> str:
        path = Path(file_path)
        try:
            return str(path.relative_to(repo_path))
        except ValueError:
            return str(path)
