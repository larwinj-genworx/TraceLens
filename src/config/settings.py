from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env", override=False)


class Settings(BaseModel):
    app_name: str = "TraceLens Distributed Validation Platform"
    app_version: str = "1.0.0"
    api_prefix: str = "/api/v1"
    analysis_workspace: Path = Field(default_factory=lambda: PROJECT_ROOT / ".workspace")
    request_timeout_seconds: int = 300
    git_clone_depth: int = 1
    docker_project_prefix: str = "tracelens"
    groq_api_key: str | None = Field(default_factory=lambda: os.getenv("GROQ_API_KEY"))
    groq_model: str = Field(default_factory=lambda: os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"))


settings = Settings()
settings.analysis_workspace.mkdir(parents=True, exist_ok=True)
