from __future__ import annotations

import time
import uuid

from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware

from src.observability.logging.setup import get_logger
from src.observability.metrics.registry import metrics_registry
from src.observability.tracing.context import request_id_ctx

logger = get_logger(__name__)


class RequestLoggingMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        request_id = request.headers.get("x-request-id", str(uuid.uuid4()))
        token = request_id_ctx.set(request_id)
        started = time.perf_counter()
        response = None
        try:
            response = await call_next(request)
            return response
        finally:
            duration = time.perf_counter() - started
            metrics_registry.observe("http_request_duration_seconds", duration)
            logger.info(
                "%s %s status=%s duration_ms=%.2f",
                request.method,
                request.url.path,
                getattr(locals().get("response"), "status_code", "error"),
                duration * 1000,
                extra={"request_id": request_id},
            )
            request_id_ctx.reset(token)
            if response is not None:
                response.headers["x-request-id"] = request_id


def setup_request_logging(app: FastAPI) -> None:
    app.add_middleware(RequestLoggingMiddleware)
