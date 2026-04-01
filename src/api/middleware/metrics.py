from __future__ import annotations

from fastapi import APIRouter, FastAPI

from src.observability.metrics.registry import metrics_registry


metrics_router = APIRouter(tags=["metrics"])


@metrics_router.get("/metrics")
async def get_metrics() -> dict:
    return metrics_registry.snapshot()


def setup_metrics(app: FastAPI) -> None:
    app.include_router(metrics_router)
