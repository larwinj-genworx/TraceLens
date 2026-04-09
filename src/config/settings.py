from __future__ import annotations

import os
from pathlib import Path

from pydantic import BaseModel, Field
from dotenv import load_dotenv


PROJECT_ROOT = Path(__file__).resolve().parents[2]
load_dotenv(PROJECT_ROOT / ".env", override=False)


def _load_api_keys() -> list[str]:
    """Load GROQ API keys from GROQ_API_KEYS (comma-separated) or single GROQ_API_KEY."""
    pool = os.getenv("GROQ_API_KEYS", "")
    keys = [k.strip() for k in pool.split(",") if k.strip()]
    if keys:
        return keys
    single = os.getenv("GROQ_API_KEY", "")
    return [single] if single else []


class Settings(BaseModel):
    app_name: str = "TraceLens Distributed Validation Platform"
    app_version: str = "1.0.0"
    api_prefix: str = "/api/v1"
    analysis_workspace: Path = Field(default_factory=lambda: PROJECT_ROOT / ".workspace")
    request_timeout_seconds: int = 300
    git_clone_depth: int = 1
    docker_project_prefix: str = "tracelens"
    groq_api_key: str | None = Field(default_factory=lambda: os.getenv("GROQ_API_KEY"))
    groq_api_keys: list[str] = Field(default_factory=_load_api_keys)
    groq_model: str = Field(default_factory=lambda: os.getenv("GROQ_MODEL", "llama-3.3-70b-versatile"))

    analysis_mode: str = Field(
        default_factory=lambda: os.getenv("ANALYSIS_MODE", "agentic"),
        description="agentic | deterministic | hybrid",
    )
    groq_scanner_model: str = Field(
        default_factory=lambda: os.getenv("GROQ_SCANNER_MODEL", "llama-3.3-70b-versatile"),
    )
    groq_reviewer_model: str = Field(
        default_factory=lambda: os.getenv("GROQ_REVIEWER_MODEL", "llama-3.3-70b-versatile"),
    )
    groq_max_retries: int = 5
    groq_retry_delay_seconds: float = 2.0
    groq_rate_limit_rpm: int = 30
    groq_request_timeout_seconds: int = 60
    agent_max_issues_per_scan: int = 50
    agent_evidence_max_tokens: int = 3000
    agent_include_code_snippets: bool = True
    agent_code_snippet_lines: int = 10

    evidence_trace_enabled: bool = Field(
        default_factory=lambda: os.getenv("EVIDENCE_TRACE_ENABLED", "false").lower() == "true",
        description="Dump agent evidence and intermediate state to trace files",
    )
    evidence_trace_dir: Path = Field(
        default_factory=lambda: PROJECT_ROOT / ".traces",
    )
    strict_standards_mode: bool = Field(
        default_factory=lambda: os.getenv("STRICT_STANDARDS_MODE", "true").lower() == "true",
        description="Enable strict standards-driven checks and evidence-to-issue conversion.",
    )


settings = Settings()
settings.analysis_workspace.mkdir(parents=True, exist_ok=True)
if settings.evidence_trace_enabled:
    settings.evidence_trace_dir.mkdir(parents=True, exist_ok=True)
