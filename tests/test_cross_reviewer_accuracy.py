"""Tests for cross-reviewer accuracy: deterministic issue protection, batching, enriched evidence."""
from __future__ import annotations

import json
from typing import Any
from unittest.mock import AsyncMock, patch

import pytest

from src.agents.nodes.cross_reviewer import (
    _BATCH_SIZE,
    _BATCH_THRESHOLD,
    _build_deterministic_keys,
    _compact_evidence_summary,
    _reinject_deterministic,
    _tag_deterministic,
    review_issues,
)
from src.agents.state import AgentState
from src.schemas.internal import (
    AnalysisContext,
    BackendEndpoint,
    EnvInferenceResult,
    FlowCoverageItem,
    FlowStatus,
    GraphBuildResult,
    RepoDescriptor,
    RepoType,
    SchemaField,
    StaticAnalysisResult,
)
from src.schemas.issues import Issue, Severity


def _make_issue(
    issue_type: str = "missing_auth",
    severity: Severity = Severity.CRITICAL,
    endpoint: str | None = "GET /test",
    confidence: float = 0.85,
    service: str = "backend",
) -> Issue:
    return Issue(
        type=issue_type,
        severity=severity,
        service=service,
        endpoint=endpoint,
        description=f"Test {issue_type}",
        impact="Test impact",
        fix="Test fix",
        confidence=confidence,
        source="test_analyst",
    )


def _make_flow_coverage(flow_id: str, endpoint: str, status: FlowStatus) -> dict[str, Any]:
    return {
        "flow": flow_id,
        "ep": endpoint,
        "svc": "backend",
        "status": status.value,
    }


def _make_evidence_package() -> dict[str, Any]:
    return {
        "full": {
            "endpoints": [
                {"svc": "backend", "path": "/test", "method": "GET", "deps": [], "sensitive": []},
                {"svc": "backend", "path": "/admin", "method": "POST", "deps": ["Depends(get_current_user)"], "sensitive": []},
            ],
            "graph_matches": [
                {"fe_url": "/api/test", "fe_method": "GET", "be_path": "/test", "be_method": "GET"},
            ],
            "unmatched_calls": [
                {"url": "/api/missing", "method": "GET", "svc": "frontend"},
            ],
            "contract_violations": [
                {"type": "missing_fields", "endpoint": "GET /test", "service": "backend", "description": "field X missing"},
            ],
            "flow_coverage": [
                _make_flow_coverage("authn_flow", "GET /test", FlowStatus.MISSING),
                _make_flow_coverage("authn_flow", "POST /admin", FlowStatus.COVERED),
                _make_flow_coverage("authz_flow", "POST /admin", FlowStatus.MISSING),
                _make_flow_coverage("rate_limit_flow", "POST /login", FlowStatus.MISSING),
            ],
        }
    }


class TestBuildDeterministicKeys:
    def test_extracts_missing_flows(self):
        evidence = _make_evidence_package()["full"]
        keys = _build_deterministic_keys(evidence)
        assert ("missing_auth", "GET /test") in keys
        assert ("missing_authz_flow", "POST /admin") in keys
        assert ("missing_rate_limit_flow", "POST /login") in keys

    def test_ignores_covered_flows(self):
        evidence = _make_evidence_package()["full"]
        keys = _build_deterministic_keys(evidence)
        assert ("missing_auth", "POST /admin") not in keys

    def test_empty_flow_coverage(self):
        keys = _build_deterministic_keys({"flow_coverage": []})
        assert len(keys) == 0


class TestTagDeterministic:
    def test_tags_matching_candidates(self):
        det_keys = {("missing_auth", "GET /test")}
        candidates = [
            {"type": "missing_auth", "endpoint": "GET /test"},
            {"type": "data_leakage", "endpoint": "GET /users"},
        ]
        _tag_deterministic(candidates, det_keys)
        assert candidates[0]["deterministic_backing"] is True
        assert candidates[1]["deterministic_backing"] is False


class TestReinjectDeterministic:
    def test_reinjects_dropped_issues(self):
        det_keys = {("missing_auth", "GET /test"), ("missing_authz_flow", "POST /admin")}
        original = [
            _make_issue("missing_auth", endpoint="GET /test"),
            _make_issue("missing_authz_flow", endpoint="POST /admin"),
            _make_issue("data_leakage", endpoint="GET /users"),
        ]
        reviewed = [_make_issue("data_leakage", endpoint="GET /users")]

        result = _reinject_deterministic(reviewed, original, det_keys)
        types_and_endpoints = {(i.type, i.endpoint) for i in result}
        assert ("missing_auth", "GET /test") in types_and_endpoints
        assert ("missing_authz_flow", "POST /admin") in types_and_endpoints
        assert ("data_leakage", "GET /users") in types_and_endpoints

    def test_no_duplicates_when_already_kept(self):
        det_keys = {("missing_auth", "GET /test")}
        original = [_make_issue("missing_auth", endpoint="GET /test")]
        reviewed = [_make_issue("missing_auth", endpoint="GET /test")]

        result = _reinject_deterministic(reviewed, original, det_keys)
        assert len(result) == 1


class TestCompactEvidenceSummary:
    def test_includes_graph_match_details(self):
        evidence = _make_evidence_package()["full"]
        summary = _compact_evidence_summary(evidence)
        assert "graph_matches" in summary
        assert summary["graph_matches"][0]["fe_url"] == "/api/test"

    def test_includes_contract_violation_details(self):
        evidence = _make_evidence_package()["full"]
        summary = _compact_evidence_summary(evidence)
        assert "contract_violations" in summary
        assert summary["contract_violation_count"] == 1
        assert summary["contract_violations"][0]["type"] == "missing_fields"

    def test_includes_all_missing_flows(self):
        evidence = _make_evidence_package()["full"]
        summary = _compact_evidence_summary(evidence)
        assert summary["missing_flow_count"] == 3
        assert len(summary["missing_flows"]) == 3

    def test_includes_endpoint_details(self):
        evidence = _make_evidence_package()["full"]
        summary = _compact_evidence_summary(evidence)
        assert summary["endpoint_count"] == 2
        assert "svc" in summary["endpoints"][0]


class TestBatchReview:
    def test_batch_threshold(self):
        assert _BATCH_THRESHOLD == 15
        assert _BATCH_SIZE == 10

    def test_batched_review_invoked_for_large_sets(self):
        """When consolidated issues exceed threshold, batched review should be used."""
        import asyncio

        issues = [_make_issue(endpoint=f"GET /ep{i}") for i in range(20)]
        evidence = _make_evidence_package()

        state: AgentState = {
            "job_id": "test-batch",
            "analysis_context": None,  # type: ignore[typeddict-item]
            "evidence_package": evidence,
            "consolidated_issues": issues,
            "security_issues": [],
            "integration_issues": [],
            "quality_issues": [],
            "reviewed_issues": [],
            "report": None,
            "progress_events": [],
            "errors": [],
        }

        mock_response = json.dumps({
            "verified_issues": [
                {
                    "type": "missing_auth",
                    "severity": "critical",
                    "service": "backend",
                    "endpoint": f"GET /ep{i}",
                    "description": f"Missing auth on ep{i}",
                    "impact": "Unauthorized access",
                    "fix": "Add auth",
                    "confidence": 0.85,
                }
                for i in range(5)
            ]
        })

        async def _run():
            with patch("src.agents.nodes.cross_reviewer.RateLimitedGroqClient") as MockClient:
                instance = AsyncMock()
                instance.invoke = AsyncMock(return_value=mock_response)
                MockClient.return_value = instance

                result = await review_issues(state)
                reviewed = result["reviewed_issues"]
                assert instance.invoke.call_count >= 2
                assert len(reviewed) >= 5

        asyncio.run(_run())
