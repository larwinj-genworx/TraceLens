from __future__ import annotations

import asyncio

from fastapi import APIRouter, Depends, HTTPException

from src.api.rest.dependencies import AnalysisJobManager, get_analysis_service, get_job_manager
from src.core.services.analysis_service import AnalysisService
from src.schemas.input import AnalysisRequest
from src.schemas.report import AnalysisReport

router = APIRouter(prefix="/analysis", tags=["analysis"])


@router.post("", response_model=AnalysisReport)
async def analyze(
    payload: AnalysisRequest,
    service: AnalysisService = Depends(get_analysis_service),
) -> AnalysisReport:
    return await service.analyze(payload)


@router.post("/async")
async def analyze_async(
    payload: AnalysisRequest,
    service: AnalysisService = Depends(get_analysis_service),
    jobs: AnalysisJobManager = Depends(get_job_manager),
) -> dict[str, str]:
    job_id = await jobs.create_job()

    async def progress(event: dict) -> None:
        await jobs.publish_event(job_id, event)

    async def runner() -> None:
        try:
            result = await service.analyze(payload, progress_cb=progress)
            await jobs.complete(job_id, result)
            await jobs.publish_event(job_id, {"stage": "complete", "message": "Analysis completed"})
        except Exception as exc:  # noqa: BLE001
            await jobs.fail(job_id, str(exc))
            await jobs.publish_event(job_id, {"stage": "failed", "message": str(exc)})

    asyncio.create_task(runner())
    return {"job_id": job_id, "status": "running"}


@router.get("/jobs/{job_id}")
async def get_job_status(job_id: str, jobs: AnalysisJobManager = Depends(get_job_manager)) -> dict:
    job = await jobs.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job_not_found")
    return job
