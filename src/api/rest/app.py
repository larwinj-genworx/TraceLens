from __future__ import annotations

from pathlib import Path

from fastapi import APIRouter, FastAPI
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles

from src.api.middleware.cors import setup_cors
from src.api.middleware.error_handler import setup_exception_handlers
from src.api.middleware.logging import setup_request_logging
from src.api.middleware.metrics import setup_metrics
from src.api.rest.routes.analysis import router as analysis_router
from src.api.rest.routes.health import router as health_router
from src.api.rest.routes.sse import router as sse_router
from src.api.rest.routes.websocket import router as websocket_router
from src.config.settings import settings
from src.observability.logging.setup import configure_logging


def create_app() -> FastAPI:
    configure_logging()

    app = FastAPI(
        title=settings.app_name,
        version=settings.app_version,
        docs_url="/docs",
        redoc_url="/redoc",
    )

    setup_cors(app)
    setup_request_logging(app)
    setup_exception_handlers(app)
    setup_metrics(app)

    # Required root endpoints (e.g., POST /analysis)
    app.include_router(health_router)
    app.include_router(analysis_router)
    app.include_router(sse_router)
    app.include_router(websocket_router)

    # Optional versioned aliases
    if settings.api_prefix:
        api_router = APIRouter(prefix=settings.api_prefix)
        api_router.include_router(health_router)
        api_router.include_router(analysis_router)
        api_router.include_router(sse_router)
        api_router.include_router(websocket_router)
        app.include_router(api_router)

    frontend_dir = Path(__file__).resolve().parents[3] / "frontend"
    if frontend_dir.exists():
        app.mount("/ui", StaticFiles(directory=str(frontend_dir), html=True), name="ui")

        @app.get("/", include_in_schema=False)
        async def root_redirect() -> RedirectResponse:
            return RedirectResponse(url="/ui")
    else:

        @app.get("/", include_in_schema=False)
        async def docs_redirect() -> RedirectResponse:
            return RedirectResponse(url="/docs")

    return app
