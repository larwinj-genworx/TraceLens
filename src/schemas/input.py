from __future__ import annotations

from pydantic import BaseModel, Field, HttpUrl, field_validator


class RepoInput(BaseModel):
    """A single repository to analyse, with an optional branch override."""

    url: str = Field(..., description="Git repository URL (https:// or git@).")
    branch: str | None = Field(
        default=None,
        description="Branch to clone. Omit to use the remote's default branch.",
    )

    @field_validator("url")
    @classmethod
    def validate_url(cls, value: str) -> str:
        value = value.strip()
        if not value:
            raise ValueError("Repository URL cannot be empty.")
        if not (
            value.startswith("http://")
            or value.startswith("https://")
            or value.startswith("git@")
        ):
            raise ValueError(f"Unsupported repository URL format: {value!r}")
        return value

    @field_validator("branch")
    @classmethod
    def validate_branch(cls, value: str | None) -> str | None:
        if value is None:
            return None
        stripped = value.strip()
        return stripped if stripped else None


class AnalysisRequest(BaseModel):
    repos: list[RepoInput | str | HttpUrl] = Field(
        ...,
        min_length=1,
        description=(
            "List of repositories to analyse. Each entry may be a plain URL string "
            "or an object with {url, branch} keys."
        ),
    )
    enable_runtime: bool = Field(default=True, description="Run runtime dockerized validation.")
    enable_llm_enhancement: bool = Field(default=True, description="Enable Groq-generated explanations and fixes.")
    runtime_timeout_seconds: int = Field(default=240, ge=30, le=1800)

    @field_validator("repos", mode="before")
    @classmethod
    def coerce_repos(cls, value: object) -> list[RepoInput]:
        """Normalise every entry to a RepoInput regardless of whether the caller
        sent a plain URL string or a {url, branch} dict / RepoInput object."""
        if not isinstance(value, list):
            raise ValueError("repos must be a list.")
        out: list[RepoInput] = []
        for item in value:
            if isinstance(item, RepoInput):
                out.append(item)
            elif isinstance(item, dict):
                out.append(RepoInput(**item))
            else:
                # Plain URL string or pydantic HttpUrl
                out.append(RepoInput(url=str(item)))
        return out
