from __future__ import annotations

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from src.core.exceptions.errors import TraceLensError
from src.observability.logging.setup import get_logger

logger = get_logger(__name__)


def setup_exception_handlers(app: FastAPI) -> None:
    @app.exception_handler(TraceLensError)
    async def handle_app_error(request: Request, exc: TraceLensError) -> JSONResponse:
        logger.error("application_error path=%s error=%s", request.url.path, str(exc), extra={"request_id": "-"})
        return JSONResponse(status_code=400, content={"error": str(exc)})

    @app.exception_handler(Exception)
    async def handle_unexpected_error(request: Request, exc: Exception) -> JSONResponse:
        logger.exception("unexpected_error path=%s", request.url.path, extra={"request_id": "-"})
        return JSONResponse(status_code=500, content={"error": "internal_server_error", "detail": str(exc)})
