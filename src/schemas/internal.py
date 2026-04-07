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
    canonical_path: str | None = None
    method: str
    is_websocket: bool = False
    request_schema: str | None = None
    request_fields: list[SchemaField] = Field(default_factory=list)
    response_schema: str | None = None
    response_fields: list[SchemaField] = Field(default_factory=list)
    redacted_response_fields: list[str] = Field(default_factory=list)
    dependencies: list[str] = Field(default_factory=list)
    function_name: str | None = None
    decorators: list[str] = Field(default_factory=list)
    call_refs: list[str] = Field(default_factory=list)
    string_refs: list[str] = Field(default_factory=list)
    has_try_except: bool = False
    route_intent: str | None = None
    auth_mode: str | None = None
    ownership_mode: str | None = None


class FrontendCall(BaseModel):
    service: str
    file: str
    line: int | None = None
    raw_url: str
    resolved_url: str | None = None
    canonical_url: str | None = None
    canonical_path: str | None = None
    method: str = "GET"
    payload_fields: dict[str, str] = Field(default_factory=dict)
    payload_unresolved: bool = False
    payload_resolution: str | None = None
    url_unresolved: bool = False
    headers: dict[str, str] = Field(default_factory=dict)
    env_vars: list[str] = Field(default_factory=list)


class CorsConfig(BaseModel):
    allow_origins: list[str] = Field(default_factory=list)
    allow_methods: list[str] = Field(default_factory=list)
    allow_headers: list[str] = Field(default_factory=list)
    allow_credentials: bool = False
    is_permissive: bool = False


class FastAPIGlobalFacts(BaseModel):
    middleware_refs: list[str] = Field(default_factory=list)
    exception_handler_refs: list[str] = Field(default_factory=list)
    global_dependencies: list[str] = Field(default_factory=list)
    module_call_refs: list[str] = Field(default_factory=list)
    cors_config: CorsConfig | None = None


class ClientStorageIssue(BaseModel):
    storage_type: str
    key: str
    operation: str
    file: str
    line: int | None = None


class StaticAnalysisResult(BaseModel):
    repo: str
    backend_endpoints: list[BackendEndpoint] = Field(default_factory=list)
    frontend_calls: list[FrontendCall] = Field(default_factory=list)
    env_references: list[str] = Field(default_factory=list)
    hardcoded_urls: list[str] = Field(default_factory=list)
    configurable_urls: list[str] = Field(default_factory=list)
    parser_errors: list[str] = Field(default_factory=list)
    fastapi_facts: FastAPIGlobalFacts = Field(default_factory=FastAPIGlobalFacts)
    client_storage_issues: list[ClientStorageIssue] = Field(default_factory=list)


class FlowStatus(str, Enum):
    COVERED = "covered"
    MISSING = "missing"
    AMBIGUOUS = "ambiguous"
    NOT_APPLICABLE = "not_applicable"


class FlowApplicability(BaseModel):
    methods: list[str] = Field(default_factory=lambda: ["*"])
    include_public: bool = True
    only_public: bool = False
    requires_mutating: bool = False
    path_markers_any: list[str] = Field(default_factory=list)
    requires_path_markers: bool = False
    exclude_path_markers: list[str] = Field(default_factory=list)
    requires_sensitive_response: bool = False
    requires_sink: bool = False
    requires_auth_sensitive: bool = False


class FlowRuleDefinition(BaseModel):
    id: str
    title: str
    description: str
    issue_type: str
    severity: str
    applies_to: FlowApplicability = Field(default_factory=FlowApplicability)
    covered_markers: list[str] = Field(default_factory=list)
    ambiguous_markers: list[str] = Field(default_factory=list)
    sink_markers: list[str] = Field(default_factory=list)
    sanitizer_markers: list[str] = Field(default_factory=list)
    missing_description: str
    missing_impact: str
    missing_fix: str


class FlowCoverageItem(BaseModel):
    flow_id: str
    service: str
    endpoint: str
    file: str | None = None
    line: int | None = None
    status: FlowStatus
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)


class FlowSummaryItem(BaseModel):
    flow_id: str
    title: str
    covered: int = 0
    missing: int = 0
    ambiguous: int = 0
    not_applicable: int = 0


class Observation(BaseModel):
    flow_id: str
    service: str
    endpoint: str | None = None
    file: str | None = None
    line: int | None = None
    message: str
    confidence: float = Field(default=0.5, ge=0.0, le=1.0)
    evidence: dict[str, Any] = Field(default_factory=dict)


class MandatoryFlowResult(BaseModel):
    catalog_version: str
    flow_definitions: dict[str, FlowRuleDefinition] = Field(default_factory=dict)
    flow_coverage: list[FlowCoverageItem] = Field(default_factory=list)
    flow_summary: list[FlowSummaryItem] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)


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
    external_calls: list[FrontendCall] = Field(default_factory=list)
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


class TypeDiagnostic(BaseModel):
    repo: str
    tool: str
    status: str
    message: str
    file: str | None = None
    line: int | None = None
    code: str | None = None


class AnalysisContext(BaseModel):
    repos: list[RepoDescriptor]
    static_results: dict[str, StaticAnalysisResult]
    env_result: EnvInferenceResult
    graph_result: GraphBuildResult
    contract_issues: list[dict[str, Any]] = Field(default_factory=list)
    runtime_result: RuntimeExecutionResult | None = None
    flow_catalog_version: str | None = None
    flow_definitions: dict[str, FlowRuleDefinition] = Field(default_factory=dict)
    flow_coverage: list[FlowCoverageItem] = Field(default_factory=list)
    flow_summary: list[FlowSummaryItem] = Field(default_factory=list)
    observations: list[Observation] = Field(default_factory=list)
    type_diagnostics: list[TypeDiagnostic] = Field(default_factory=list)
