from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class RepoType(str, Enum):
    FRONTEND = "frontend"
    BACKEND = "backend"
    MIXED = "mixed"
    UNKNOWN = "unknown"


class RepoDescriptor(BaseModel):
    name: str
    url: str
    local_path: str
    repo_type: RepoType
    detected_ports: list[int] = Field(default_factory=list)
    fastapi_entrypoint: str | None = None
    frontend_start_script: str | None = None
    clone_error: str | None = None


class SchemaField(BaseModel):
    name: str
    field_type: str
    required: bool = True


class BackendEndpoint(BaseModel):
    service: str
    file: str
    line: int | None = None
    path: str
    method: str
    request_schema: str | None = None
    request_fields: list[SchemaField] = Field(default_factory=list)
    response_schema: str | None = None
    response_fields: list[SchemaField] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)


class FrontendCall(BaseModel):
    service: str
    file: str
    line: int | None = None
    raw_url: str
    resolved_url: str | None = None
    method: str = "GET"
    payload_fields: dict[str, str] = Field(default_factory=dict)
    headers: dict[str, str] = Field(default_factory=dict)
    env_vars: list[str] = Field(default_factory=list)


class StaticAnalysisResult(BaseModel):
    repo: str
    backend_endpoints: list[BackendEndpoint] = Field(default_factory=list)
    frontend_calls: list[FrontendCall] = Field(default_factory=list)
    env_references: list[str] = Field(default_factory=list)
    hardcoded_urls: list[str] = Field(default_factory=list)
    parser_errors: list[str] = Field(default_factory=list)


class EnvInferenceResult(BaseModel):
    inferred_env: dict[str, dict[str, str]] = Field(default_factory=dict)
    assumptions: list[str] = Field(default_factory=list)
    service_base_urls: dict[str, str] = Field(default_factory=dict)


class ServiceMatch(BaseModel):
    frontend_repo: str
    backend_repo: str
    call: FrontendCall
    endpoint: BackendEndpoint
    match_score: float = 0.0


class GraphBuildResult(BaseModel):
    matches: list[ServiceMatch] = Field(default_factory=list)
    unmatched_calls: list[FrontendCall] = Field(default_factory=list)
    graph_edges: list[dict[str, Any]] = Field(default_factory=list)


class RuntimeProbe(BaseModel):
    service: str
    method: str
    url: str
    status_code: int | None = None
    request_headers: dict[str, str] = Field(default_factory=dict)
    response_headers: dict[str, str] = Field(default_factory=dict)
    response_body_snippet: str | None = None
    error: str | None = None


class RuntimeExecutionResult(BaseModel):
    compose_file: str | None = None
    service_status: dict[str, str] = Field(default_factory=dict)
    probes: list[RuntimeProbe] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)


class AnalysisContext(BaseModel):
    repos: list[RepoDescriptor]
    static_results: dict[str, StaticAnalysisResult]
    env_result: EnvInferenceResult
    graph_result: GraphBuildResult
    contract_issues: list[dict[str, Any]] = Field(default_factory=list)
    runtime_result: RuntimeExecutionResult | None = None
