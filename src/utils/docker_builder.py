from __future__ import annotations

import re
from pathlib import Path

import yaml

from src.schemas.internal import RepoDescriptor, RepoType


class DockerComposeBuilder:
    def build(
        self,
        repos: list[RepoDescriptor],
        inferred_env: dict[str, dict[str, str]],
    ) -> tuple[dict, dict[str, int]]:
        services: dict[str, dict] = {}
        used_ports: set[int] = set()
        runtime_ports: dict[str, int] = {}

        for repo in repos:
            if repo.clone_error:
                continue

            runtime_kind = self._resolve_runtime_kind(repo)
            if runtime_kind is None:
                continue

            service_name = self._sanitize_service_name(repo.name)
            container_port = repo.detected_ports[0] if repo.detected_ports else (8000 if runtime_kind == "backend" else 3000)
            host_port = self._allocate_port(container_port, used_ports)
            runtime_ports[repo.name] = host_port

            env = dict(inferred_env.get(repo.name, {}))
            env.setdefault("PORT", str(container_port))

            dockerfile = Path(repo.local_path) / "Dockerfile"
            if dockerfile.exists():
                service_def = {
                    "build": {"context": repo.local_path, "dockerfile": "Dockerfile"},
                    "container_name": f"tracelens_{service_name}",
                    "ports": [f"{host_port}:{container_port}"],
                    "environment": env,
                    "networks": ["tracelens_net"],
                }
            elif runtime_kind == "backend":
                entrypoint = repo.fastapi_entrypoint or "main"
                command = (
                    "sh -lc \""
                    "if [ -f requirements.txt ]; then pip install --no-cache-dir -r requirements.txt; "
                    "else pip install --no-cache-dir fastapi uvicorn pydantic; fi && "
                    f"uvicorn {entrypoint}:app --host 0.0.0.0 --port {container_port}"
                    "\""
                )
                service_def = {
                    "image": "python:3.11-slim",
                    "working_dir": "/workspace",
                    "volumes": [f"{repo.local_path}:/workspace"],
                    "command": command,
                    "container_name": f"tracelens_{service_name}",
                    "ports": [f"{host_port}:{container_port}"],
                    "environment": env,
                    "networks": ["tracelens_net"],
                }
            else:
                start_script = repo.frontend_start_script or "dev"
                command = (
                    "sh -lc \""
                    "if [ -f package-lock.json ]; then npm ci; "
                    "elif [ -f yarn.lock ]; then yarn install; "
                    "elif [ -f pnpm-lock.yaml ]; then npm install -g pnpm && pnpm install; "
                    "else npm install; fi && "
                    f"(npm run {start_script} -- --host 0.0.0.0 --port {container_port} "
                    f"|| npm run dev -- --host 0.0.0.0 --port {container_port} "
                    f"|| npm start -- --host 0.0.0.0 --port {container_port})"
                    "\""
                )
                service_def = {
                    "image": "node:20-alpine",
                    "working_dir": "/workspace",
                    "volumes": [f"{repo.local_path}:/workspace"],
                    "command": command,
                    "container_name": f"tracelens_{service_name}",
                    "ports": [f"{host_port}:{container_port}"],
                    "environment": env,
                    "networks": ["tracelens_net"],
                }

            services[service_name] = service_def

        compose_spec = {
            "services": services,
            "networks": {"tracelens_net": {"driver": "bridge"}},
        }
        return compose_spec, runtime_ports

    def write(self, compose_spec: dict, output_path: Path) -> None:
        output_path.parent.mkdir(parents=True, exist_ok=True)
        output_path.write_text(yaml.safe_dump(compose_spec, sort_keys=False), encoding="utf-8")

    def _resolve_runtime_kind(self, repo: RepoDescriptor) -> str | None:
        if repo.repo_type == RepoType.BACKEND:
            return "backend"
        if repo.repo_type == RepoType.FRONTEND:
            return "frontend"
        if repo.repo_type == RepoType.MIXED:
            if repo.fastapi_entrypoint:
                return "backend"
            if repo.frontend_start_script:
                return "frontend"
            return "backend"
        return None

    def _sanitize_service_name(self, value: str) -> str:
        cleaned = re.sub(r"[^a-zA-Z0-9]", "-", value.lower()).strip("-")
        return cleaned or "service"

    def _allocate_port(self, preferred: int, used_ports: set[int]) -> int:
        port = preferred
        while port in used_ports:
            port += 1
        used_ports.add(port)
        return port
