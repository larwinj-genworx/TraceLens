from __future__ import annotations

import asyncio
import hashlib
import io
import json
import shutil
import zipfile
from pathlib import Path
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, UploadFile
from fastapi.responses import StreamingResponse

from src.api.rest.dependencies import AnalysisJobManager, get_analysis_service, get_job_manager
from src.config.settings import settings
from src.core.services.analysis_service import AnalysisService
from src.schemas.input import AnalysisRequest, RepoInput
from src.schemas.report import AnalysisReport
from src.observability.logging.setup import get_logger

logger = get_logger(__name__)

router = APIRouter(prefix="/analysis", tags=["analysis"])


def _build_upload_request(repo_inputs: list[RepoInput], cfg: dict[str, Any]) -> AnalysisRequest:
    return AnalysisRequest(
        repos=repo_inputs,
        enable_runtime=cfg.get("enable_runtime", True),
        enable_llm_enhancement=cfg.get("enable_llm_enhancement", True),
        runtime_timeout_seconds=cfg.get("runtime_timeout_seconds", 240),
        standard_id=cfg.get("standard_id"),
    )


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
            result = await service.analyze(payload, progress_cb=progress, job_id=job_id)
            await jobs.complete(job_id, result)
            await jobs.publish_event(job_id, {"stage": "complete", "message": "Analysis completed"})
        except Exception as exc:  # noqa: BLE001
            await jobs.fail(job_id, str(exc))
            await jobs.publish_event(job_id, {"stage": "failed", "message": str(exc)})

    asyncio.create_task(runner())
    return {"job_id": job_id, "status": "running"}


@router.post("/upload")
async def analyze_upload(
    repos: list[UploadFile] = File(..., description="ZIP archives of repository source code"),
    config: str = Form(default="{}"),
    service: AnalysisService = Depends(get_analysis_service),
    jobs: AnalysisJobManager = Depends(get_job_manager),
) -> dict[str, str]:
    """Accept ZIP file uploads, extract them, and run analysis."""
    try:
        cfg: dict[str, Any] = json.loads(config)
    except json.JSONDecodeError:
        raise HTTPException(status_code=400, detail="config must be valid JSON")

    workspace = settings.analysis_workspace
    repo_inputs: list[RepoInput] = []
    url_repos: list[dict[str, Any]] = cfg.get("url_repos", [])

    for url_repo in url_repos:
        repo_inputs.append(RepoInput(**url_repo))

    for upload in repos:
        if not upload.filename:
            raise HTTPException(status_code=400, detail="Each uploaded file must have a filename")

        if not upload.filename.lower().endswith(".zip"):
            raise HTTPException(status_code=400, detail=f"Only .zip files accepted, got: {upload.filename}")

        content = await upload.read()
        name_stem = Path(upload.filename).stem
        sanitized = "".join(c if c.isalnum() or c in "-_" else "_" for c in name_stem)
        unique_suffix = hashlib.sha1(content[:1024]).hexdigest()[:8]
        target_dir = workspace / f"{sanitized}-{unique_suffix}"

        if target_dir.exists():
            shutil.rmtree(target_dir)
        target_dir.mkdir(parents=True, exist_ok=True)

        try:
            with zipfile.ZipFile(io.BytesIO(content)) as zf:
                zf.extractall(target_dir)
        except zipfile.BadZipFile:
            shutil.rmtree(target_dir, ignore_errors=True)
            raise HTTPException(status_code=400, detail=f"Invalid ZIP file: {upload.filename}")

        top_entries = list(target_dir.iterdir())
        if len(top_entries) == 1 and top_entries[0].is_dir():
            target_dir = top_entries[0]

        repo_inputs.append(RepoInput(
            url="",
            source_type="zip",
            local_path=str(target_dir),
        ))

    if not repo_inputs:
        raise HTTPException(status_code=400, detail="No repositories provided (neither ZIPs nor URLs)")

    request = _build_upload_request(repo_inputs, cfg)

    job_id = await jobs.create_job()

    async def progress(event: dict) -> None:
        await jobs.publish_event(job_id, event)

    async def runner() -> None:
        try:
            result = await service.analyze(request, progress_cb=progress, job_id=job_id)
            await jobs.complete(job_id, result)
            await jobs.publish_event(job_id, {"stage": "complete", "message": "Analysis completed"})
        except Exception as exc:  # noqa: BLE001
            logger.exception("upload analysis failed job_id=%s", job_id)
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


@router.get("/jobs/{job_id}/trace")
async def get_job_trace(job_id: str) -> StreamingResponse:
    """Download evidence trace files as a ZIP archive."""
    if not settings.evidence_trace_enabled:
        raise HTTPException(status_code=404, detail="evidence_tracing_disabled")

    trace_dir = settings.evidence_trace_dir / job_id
    if not trace_dir.is_dir():
        raise HTTPException(status_code=404, detail="trace_not_found")

    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        for fpath in sorted(trace_dir.iterdir()):
            if fpath.is_file() and fpath.suffix == ".json":
                zf.write(fpath, fpath.name)
    buf.seek(0)

    return StreamingResponse(
        buf,
        media_type="application/zip",
        headers={"Content-Disposition": f"attachment; filename=trace-{job_id}.zip"},
    )
