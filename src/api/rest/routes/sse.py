from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from src.api.rest.dependencies import AnalysisJobManager, get_job_manager

router = APIRouter(prefix="/analysis", tags=["stream"])


@router.get("/jobs/{job_id}/events")
async def stream_events(job_id: str, jobs: AnalysisJobManager = Depends(get_job_manager)) -> StreamingResponse:
    job = await jobs.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job_not_found")

    async def event_generator():
        history = await jobs.get_events(job_id)
        for event in history:
            yield f"data: {json.dumps(event)}\n\n"

        queue = await jobs.subscribe(job_id)
        if queue is None:
            yield "event: error\ndata: job_not_found\n\n"
            return

        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=20)
                except TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield f"data: {json.dumps(event)}\n\n"
                if event.get("stage") in {"complete", "failed"}:
                    break
        finally:
            await jobs.unsubscribe(job_id, queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
