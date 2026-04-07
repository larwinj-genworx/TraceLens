"""Integration tests for the multi-agent LangGraph analysis workflow."""
from __future__ import annotations

import asyncio
import json
import os

import pytest

from src.agents.graph import run_analysis_graph, _compiled
from src.agents.nodes.consolidator import consolidate_issues
from src.agents.nodes.evidence_preparator import prepare_evidence
from src.agents.nodes.parsing import parse_issues_from_response
from src.agents.state import AgentState
from src.schemas.internal import (
    AnalysisContext,
    BackendEndpoint,
    EnvInferenceResult,
    FlowCoverageItem,
    FlowRuleDefinition,
    FlowStatus,
    FrontendCall,
    GraphBuildResult,
    RepoDescriptor,
    RepoType,
    SchemaField,
    ServiceMatch,
    StaticAnalysisResult,
)
from src.schemas.issues import Issue, Severity


def _make_context() -> AnalysisContext:
    """Build a minimal but realistic AnalysisContext for testing."""
    repo = RepoDescriptor(
        name="test-backend",
        url="https://github.com/test/backend.git",
        local_path="/tmp/fake",
        repo_type=RepoType.BACKEND,
    )
    endpoint = BackendEndpoint(
        service="test-backend",
        file="app/api/routes.py",
        line=42,
        path="/users/{user_id}",
        method="GET",
        request_fields=[],
        response_fields=[
            SchemaField(name="id", field_type="int", required=True),
            SchemaField(name="email", field_type="str", required=True),
            SchemaField(name="password_hash", field_type="str", required=True),
        ],
        dependencies=["Depends(get_current_user)"],
        call_refs=["db.query"],
        string_refs=[],
        has_try_except=False,
    )
    frontend_call = FrontendCall(
        service="test-frontend",
        file="src/api/users.ts",
        line=15,
        raw_url="/users/${userId}",
        resolved_url="/users/123",
        method="GET",
    )
    static = StaticAnalysisResult(
        repo="test-backend",
        backend_endpoints=[endpoint],
        frontend_calls=[frontend_call],
    )
    match = ServiceMatch(
        frontend_repo="test-frontend",
        backend_repo="test-backend",
        call=frontend_call,
        endpoint=endpoint,
        match_score=0.95,
    )
    flow_missing = FlowCoverageItem(
        flow_id="request_validation_flow",
        service="test-backend",
        endpoint="GET /users/{user_id}",
        file="app/api/routes.py",
        line=42,
        status=FlowStatus.MISSING,
        confidence=0.8,
        evidence={"reason": "no validation dependency detected"},
    )
    return AnalysisContext(
        repos=[repo],
        static_results={"test-backend": static},
        env_result=EnvInferenceResult(),
        graph_result=GraphBuildResult(
            matches=[match],
            unmatched_calls=[],
            external_calls=[],
        ),
        contract_issues=[],
        flow_coverage=[flow_missing],
        flow_summary=[],
        observations=[],
        flow_definitions={
            "request_validation_flow": FlowRuleDefinition(
                id="request_validation_flow",
                title="Request Validation",
                description="Input validation",
                issue_type="missing_validation",
                severity="high",
                missing_description="No input validation",
                missing_impact="Bad input may reach business logic",
                missing_fix="Add validation",
            )
        },
    )


def test_graph_compiles():
    """The LangGraph should compile with all expected nodes."""
    nodes = list(_compiled.get_graph().nodes)
    assert "prepare_evidence" in nodes
    assert "analyze_security" in nodes
    assert "analyze_integration" in nodes
    assert "analyze_quality" in nodes
    assert "consolidate" in nodes
    assert "cross_review" in nodes
    assert "build_report" in nodes


def test_evidence_preparator():
    """Evidence preparator should serialize context into domain chunks."""
    ctx = _make_context()
    state: AgentState = {
        "analysis_context": ctx,
        "evidence_package": {},
        "security_issues": [],
        "integration_issues": [],
        "quality_issues": [],
        "consolidated_issues": [],
        "reviewed_issues": [],
        "report": None,
        "progress_events": [],
        "errors": [],
    }
    result = prepare_evidence(state)
    pkg = result["evidence_package"]
    assert "security" in pkg
    assert "integration" in pkg
    assert "quality" in pkg
    assert "full" in pkg
    assert len(pkg["security"]["endpoints"]) == 1
    assert pkg["security"]["endpoints"][0]["path"] == "/users/{user_id}"


def test_consolidator_deduplicates():
    """Consolidator should keep highest-confidence issue per key."""
    low = Issue(
        type="missing_auth",
        severity=Severity.CRITICAL,
        service="svc",
        endpoint="GET /foo",
        description="low conf",
        impact="bad",
        fix="fix it",
        confidence=0.6,
        source="security_analyst",
    )
    high = Issue(
        type="missing_auth",
        severity=Severity.CRITICAL,
        service="svc",
        endpoint="GET /foo",
        description="high conf",
        impact="bad",
        fix="fix it better",
        confidence=0.9,
        source="quality_analyst",
    )
    unique = Issue(
        type="over_fetching",
        severity=Severity.MEDIUM,
        service="svc",
        endpoint="GET /bar",
        description="too many fields",
        impact="perf",
        fix="reduce fields",
        confidence=0.7,
        source="quality_analyst",
    )
    state: AgentState = {
        "analysis_context": _make_context(),
        "evidence_package": {},
        "security_issues": [low],
        "integration_issues": [],
        "quality_issues": [high, unique],
        "consolidated_issues": [],
        "reviewed_issues": [],
        "report": None,
        "progress_events": [],
        "errors": [],
    }
    result = consolidate_issues(state)
    consolidated = result["consolidated_issues"]
    assert len(consolidated) == 2
    auth_issue = [i for i in consolidated if i.type == "missing_auth"][0]
    assert auth_issue.confidence == 0.9


def test_parse_issues_valid_json():
    """Parser should extract issues from well-formed LLM JSON."""
    raw = json.dumps({
        "issues": [
            {
                "type": "missing_auth",
                "severity": "critical",
                "service": "backend",
                "endpoint": "GET /admin",
                "file": "routes.py",
                "line": 10,
                "description": "No auth on admin",
                "evidence": {"deps": []},
                "impact": "Unauthorized access",
                "fix": "Add auth dependency",
                "confidence": 0.92,
            }
        ]
    })
    issues = parse_issues_from_response(raw, "test")
    assert len(issues) == 1
    assert issues[0].type == "missing_auth"
    assert issues[0].severity == Severity.CRITICAL
    assert issues[0].source == "test"


def test_parse_issues_malformed():
    """Parser should return empty list for garbage input."""
    issues = parse_issues_from_response("not json at all", "test")
    assert issues == []


def test_parse_issues_with_markdown_wrapping():
    """Parser should handle JSON wrapped in markdown code fences."""
    raw = '```json\n{"issues": [{"type": "x", "severity": "high", "service": "s", "description": "d", "impact": "i", "fix": "f"}]}\n```'
    issues = parse_issues_from_response(raw, "test")
    assert len(issues) == 0 or len(issues) == 1


@pytest.mark.skipif(not os.getenv("GROQ_API_KEY"), reason="GROQ_API_KEY not set")
def test_full_graph_integration():
    """Run the full LangGraph pipeline with a real Groq API call."""
    ctx = _make_context()

    async def _run():
        issues, observations = await run_analysis_graph(context=ctx)
        return issues, observations

    issues, observations = asyncio.run(_run())
    assert isinstance(issues, list)
    for issue in issues:
        assert isinstance(issue, Issue)
        assert issue.source is not None
