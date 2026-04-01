from __future__ import annotations

import asyncio
import inspect
import json
import shutil
import subprocess
import uuid
from pathlib import Path
from typing import Any, Awaitable, Callable

from src.config.settings import settings
from src.observability.logging.setup import get_logger
from src.runtime.traffic_inspector import TrafficInspector
from src.schemas.internal import EnvInferenceResult, GraphBuildResult, RepoDescriptor, RuntimeExecutionResult
from src.utils.docker_builder import DockerComposeBuilder

logger = get_logger(__name__)

RuntimeProgressCallback = Callable[[dict[str, Any]], Awaitable[None] | None]


class RuntimeOrchestrator:
    def __init__(self) -> None:
        self.builder = DockerComposeBuilder()
        self.inspector = TrafficInspector()

    async def execute(
        self,
        repos: list[RepoDescriptor],
        env_result: EnvInferenceResult,
        graph_result: GraphBuildResult,
        timeout_seconds: int = 240,
        progress_cb: RuntimeProgressCallback | None = None,
    ) -> RuntimeExecutionResult:
        errors: list[str] = []

        if not self._docker_cli_available():
            await self._emit(progress_cb, "runtime_docker_check", "Docker CLI unavailable")
            return RuntimeExecutionResult(errors=["Docker CLI is unavailable; runtime validation skipped."])
        if not self._docker_daemon_available():
            await self._emit(progress_cb, "runtime_docker_check", "Docker daemon not reachable")
            return RuntimeExecutionResult(
                errors=[
                    "Docker daemon is not reachable. Start Docker engine/desktop and re-run runtime validation."
                ]
            )

        compose_spec, runtime_ports = self.builder.build(repos, env_result.inferred_env)
        if not compose_spec.get("services"):
            return RuntimeExecutionResult(errors=["No runnable services could be inferred for runtime execution."])
        await self._emit(
            progress_cb,
            "runtime_plan",
            "Runtime compose specification generated",
            payload={"services": sorted(compose_spec.get("services", {}).keys())},
        )

        run_id = uuid.uuid4().hex[:8]
        runtime_dir = settings.analysis_workspace / "runtime" / run_id
        compose_file = runtime_dir / "docker-compose.generated.yml"
        runtime_dir.mkdir(parents=True, exist_ok=True)
        self.builder.write(compose_spec, compose_file)
        await self._emit(
            progress_cb,
            "runtime_prepare",
            "Runtime compose file prepared",
            payload={"compose_file": str(compose_file)},
        )

        project_name = f"{settings.docker_project_prefix}-{run_id}"
        up_cmd = ["docker", "compose", "-f", str(compose_file), "-p", project_name, "up", "-d", "--build"]
        down_cmd = ["docker", "compose", "-f", str(compose_file), "-p", project_name, "down", "-v", "--remove-orphans"]

        service_status: dict[str, str] = {}
        probes = []

        try:
            await self._emit(progress_cb, "runtime_up", "Starting docker compose services")
            up = await asyncio.to_thread(self._run_command, up_cmd, timeout_seconds)
            if up.returncode != 0:
                errors.append(f"docker compose up failed: {up.stderr.strip()[:500]}")
                await self._emit(
                    progress_cb,
                    "runtime_up",
                    "docker compose up failed",
                    payload={"error": errors[-1]},
                )
                return RuntimeExecutionResult(
                    compose_file=str(compose_file),
                    service_status=service_status,
                    probes=probes,
                    errors=errors,
                )

            await asyncio.sleep(7)
            service_status = await asyncio.to_thread(self._collect_service_status, compose_file, project_name)
            await self._emit(
                progress_cb,
                "runtime_status",
                "Docker service status snapshot collected",
                payload={"service_status": service_status},
            )
            probes = await self.inspector.capture(
                matches=graph_result.matches,
                runtime_ports=runtime_ports,
                timeout_seconds=min(max(timeout_seconds // 8, 5), 30),
            )
            await self._emit(
                progress_cb,
                "runtime_probe",
                "Runtime probing completed",
                payload={
                    "probe_count": len(probes),
                    "failed_probes": sum(1 for probe in probes if probe.error or (probe.status_code and probe.status_code >= 400)),
                },
            )
        except Exception as exc:  # noqa: BLE001
            errors.append(f"Runtime execution failed: {exc}")
            logger.exception("runtime_orchestrator_failure", extra={"request_id": "-"})
            await self._emit(
                progress_cb,
                "runtime_exception",
                "Runtime orchestration exception raised",
                payload={"error": str(exc)},
            )
        finally:
            await self._emit(progress_cb, "runtime_down", "Shutting down runtime containers")
            await asyncio.to_thread(self._run_command, down_cmd, timeout_seconds)
            self._cleanup_runtime_dir(runtime_dir)

        return RuntimeExecutionResult(
            compose_file=str(compose_file),
            service_status=service_status,
            probes=probes,
            errors=errors,
        )

    def _collect_service_status(self, compose_file: Path, project_name: str) -> dict[str, str]:
        cmd = ["docker", "compose", "-f", str(compose_file), "-p", project_name, "ps", "--format", "json"]
        result = self._run_command(cmd, timeout_seconds=30)
        if result.returncode != 0:
            return {"runtime": "unavailable"}

        output = result.stdout.strip()
        if not output:
            return {}

        status: dict[str, str] = {}

        try:
            payload = json.loads(output)
            if isinstance(payload, list):
                for item in payload:
                    service = item.get("Service") or item.get("Name") or "unknown"
                    state = item.get("State") or item.get("Status") or "unknown"
                    status[service] = state
                return status
        except json.JSONDecodeError:
            pass

        for line in output.splitlines():
            try:
                item = json.loads(line)
            except json.JSONDecodeError:
                continue
            service = item.get("Service") or item.get("Name") or "unknown"
            state = item.get("State") or item.get("Status") or "unknown"
            status[service] = state

        return status

    def _run_command(self, command: list[str], timeout_seconds: int) -> subprocess.CompletedProcess:
        return subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=timeout_seconds,
            check=False,
        )

    def _docker_cli_available(self) -> bool:
        result = self._run_command(["docker", "--version"], timeout_seconds=10)
        return result.returncode == 0

    def _docker_daemon_available(self) -> bool:
        result = self._run_command(["docker", "info"], timeout_seconds=15)
        return result.returncode == 0

    def _cleanup_runtime_dir(self, runtime_dir: Path) -> None:
        if runtime_dir.exists():
            shutil.rmtree(runtime_dir, ignore_errors=True)

    async def _emit(
        self,
        callback: RuntimeProgressCallback | None,
        stage: str,
        message: str,
        payload: dict[str, Any] | None = None,
    ) -> None:
        if callback is None:
            return
        event: dict[str, Any] = {"stage": stage, "message": message}
        if payload:
            event["payload"] = payload
        result = callback(event)
        if inspect.isawaitable(result):
            await result
