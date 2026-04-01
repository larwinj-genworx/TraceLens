from __future__ import annotations

from pydantic import BaseModel, Field, HttpUrl, field_validator


class AnalysisRequest(BaseModel):
    repos: list[str | HttpUrl] = Field(
        ...,
        min_length=1,
        description="List of Git repository URLs (GitHub/public or private with pre-configured credentials).",
    )
    enable_runtime: bool = Field(default=True, description="Run runtime dockerized validation.")
    enable_llm_enhancement: bool = Field(default=True, description="Enable Groq-generated explanations and fixes.")
    runtime_timeout_seconds: int = Field(default=240, ge=30, le=1800)

    @field_validator("repos")
    @classmethod
    def validate_repo_urls(cls, urls: list[str | HttpUrl]) -> list[str | HttpUrl]:
        normalized: list[str | HttpUrl] = []
        for raw in urls:
            value = str(raw).strip()
            if not value:
                raise ValueError("Repository URL cannot be empty.")
            if not (value.startswith("http://") or value.startswith("https://") or value.startswith("git@")):
                raise ValueError(f"Unsupported repository URL format: {value}")
            normalized.append(raw)
        return normalized
