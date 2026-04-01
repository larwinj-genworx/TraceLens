from __future__ import annotations

import asyncio
import uuid
from datetime import datetime, timezone

from src.core.services.analysis_service import AnalysisService
from src.schemas.report import AnalysisReport


class AnalysisJobManager:
    def __init__(self) -> None:
        self._jobs: dict[str, dict] = {}
        self._subscribers: dict[str, set[asyncio.Queue]] = {}
        self._lock = asyncio.Lock()

    async def create_job(self) -> str:
        job_id = uuid.uuid4().hex
        async with self._lock:
            self._jobs[job_id] = {
                "id": job_id,
                "status": "running",
                "created_at": self._utc_now(),
                "updated_at": self._utc_now(),
                "events": [],
                "result": None,
                "error": None,
            }
            self._subscribers[job_id] = set()
        return job_id

    async def publish_event(self, job_id: str, event: dict) -> None:
        payload = {
            **event,
            "timestamp": self._utc_now(),
        }
        async with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["events"].append(payload)
            job["updated_at"] = self._utc_now()
            subscribers = list(self._subscribers.get(job_id, set()))
        for queue in subscribers:
            await queue.put(payload)

    async def complete(self, job_id: str, result: AnalysisReport) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["status"] = "completed"
            job["result"] = result.model_dump()
            job["updated_at"] = self._utc_now()

    async def fail(self, job_id: str, error: str) -> None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return
            job["status"] = "failed"
            job["error"] = error
            job["updated_at"] = self._utc_now()

    async def get_job(self, job_id: str) -> dict | None:
        async with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return None
            return {
                "id": job["id"],
                "status": job["status"],
                "created_at": job["created_at"],
                "updated_at": job["updated_at"],
                "result": job["result"],
                "error": job["error"],
            }

    async def get_events(self, job_id: str) -> list[dict]:
        async with self._lock:
            job = self._jobs.get(job_id)
            if not job:
                return []
            return list(job["events"])

    async def subscribe(self, job_id: str) -> asyncio.Queue | None:
        queue: asyncio.Queue = asyncio.Queue()
        async with self._lock:
            if job_id not in self._jobs:
                return None
            self._subscribers.setdefault(job_id, set()).add(queue)
        return queue

    async def unsubscribe(self, job_id: str, queue: asyncio.Queue) -> None:
        async with self._lock:
            subscribers = self._subscribers.get(job_id)
            if not subscribers:
                return
            subscribers.discard(queue)

    def _utc_now(self) -> str:
        return datetime.now(timezone.utc).isoformat()


_analysis_service = AnalysisService()
_job_manager = AnalysisJobManager()


def get_analysis_service() -> AnalysisService:
    return _analysis_service


def get_job_manager() -> AnalysisJobManager:
    return _job_manager
