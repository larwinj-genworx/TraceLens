from __future__ import annotations

from typing import Any, Awaitable, Callable

from src.control.agents.orchestrator import ValidationOrchestrator
from src.schemas.input import AnalysisRequest
from src.schemas.report import AnalysisReport

ProgressCallback = Callable[[dict[str, Any]], Awaitable[None] | None]


class AnalysisService:
    def __init__(self) -> None:
        self.orchestrator = ValidationOrchestrator()

    async def analyze(self, request: AnalysisRequest, progress_cb: ProgressCallback | None = None) -> AnalysisReport:
        return await self.orchestrator.run(request, progress_cb=progress_cb)
