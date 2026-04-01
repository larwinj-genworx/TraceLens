from __future__ import annotations

import asyncio
import json

from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect

from src.api.rest.dependencies import AnalysisJobManager, get_job_manager

router = APIRouter(tags=["websocket"])


@router.websocket("/ws/analysis/jobs/{job_id}")
async def analysis_ws(websocket: WebSocket, job_id: str, jobs: AnalysisJobManager = Depends(get_job_manager)) -> None:
    await websocket.accept()

    job = await jobs.get_job(job_id)
    if not job:
        await websocket.send_text(json.dumps({"error": "job_not_found"}))
        await websocket.close(code=4404)
        return

    history = await jobs.get_events(job_id)
    for event in history:
        await websocket.send_text(json.dumps(event))

    queue = await jobs.subscribe(job_id)
    if queue is None:
        await websocket.send_text(json.dumps({"error": "job_not_found"}))
        await websocket.close(code=4404)
        return

    try:
        while True:
            event = await queue.get()
            await websocket.send_text(json.dumps(event))
            if event.get("stage") in {"complete", "failed"}:
                break
            await asyncio.sleep(0)
    except WebSocketDisconnect:
        pass
    finally:
        await jobs.unsubscribe(job_id, queue)
        await websocket.close()
