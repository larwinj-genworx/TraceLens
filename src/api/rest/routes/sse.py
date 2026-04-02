from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, HTTPException
from fastapi.responses import StreamingResponse

from src.api.rest.dependencies import AnalysisJobManager, get_job_manager

router = APIRouter(prefix="/analysis", tags=["stream"])

_TERMINAL_STAGES = {"complete", "failed"}


@router.get("/jobs/{job_id}/events")
async def stream_events(job_id: str, jobs: AnalysisJobManager = Depends(get_job_manager)) -> StreamingResponse:
    job = await jobs.get_job(job_id)
    if not job:
        raise HTTPException(status_code=404, detail="job_not_found")

    async def event_generator():
        # ── Replay historical events ─────────────────────────────────────────
        history = await jobs.get_events(job_id)
        for event in history:
            yield f"data: {json.dumps(event)}\n\n"

        # ── Early exit if the job finished before the client connected ───────
        # Re-fetch status *after* replaying history to close the window between
        # "history contains complete event" and "we enter the live subscription
        # loop forever".  Without this check the generator would send keepalives
        # indefinitely because no further events will ever be queued.
        current = await jobs.get_job(job_id)
        if current and current.get("status") in _TERMINAL_STAGES:
            return

        # ── Subscribe to live events ──────────────────────────────────────────
        queue = await jobs.subscribe(job_id)
        if queue is None:
            yield "event: error\ndata: job_not_found\n\n"
            return

        try:
            while True:
                try:
                    event = await asyncio.wait_for(queue.get(), timeout=20)
                except TimeoutError:
                    # Keepalive comment (SSE spec allows lines beginning with ":").
                    # Also check terminal status so we don't loop forever if the
                    # job somehow completed without the complete event reaching
                    # this subscriber (very unlikely but defensive).
                    status_check = await jobs.get_job(job_id)
                    if status_check and status_check.get("status") in _TERMINAL_STAGES:
                        break
                    yield ": keepalive\n\n"
                    continue

                yield f"data: {json.dumps(event)}\n\n"
                if event.get("stage") in _TERMINAL_STAGES:
                    break
        finally:
            await jobs.unsubscribe(job_id, queue)

    return StreamingResponse(event_generator(), media_type="text/event-stream")
