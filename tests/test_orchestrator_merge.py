"""Tests for ValidationOrchestrator._merge_issues."""
from __future__ import annotations

from src.control.agents.orchestrator import ValidationOrchestrator
from src.schemas.issues import Issue, Severity


def _issue(
    issue_type: str = "missing_auth",
    service: str = "backend",
    endpoint: str | None = "GET /test",
    description: str = "default desc",
    source: str | None = None,
    confidence: float = 0.85,
) -> Issue:
    return Issue(
        type=issue_type,
        severity=Severity.CRITICAL,
        service=service,
        endpoint=endpoint,
        description=description,
        impact="impact",
        fix="fix",
        confidence=confidence,
        source=source,
    )


class TestMergeIssues:
    def setup_method(self):
        self.orchestrator = ValidationOrchestrator()

    def test_deterministic_only_issues_preserved(self):
        det = [_issue(endpoint="GET /a"), _issue(endpoint="GET /b")]
        agentic: list[Issue] = []

        result = self.orchestrator._merge_issues(agentic, det)
        endpoints = {i.endpoint for i in result}
        assert endpoints == {"GET /a", "GET /b"}
        assert len(result) == 2

    def test_agentic_only_issues_preserved(self):
        det: list[Issue] = []
        agentic = [_issue(endpoint="GET /a", source="security_analyst")]

        result = self.orchestrator._merge_issues(agentic, det)
        assert len(result) == 1
        assert result[0].source == "security_analyst"

    def test_agentic_takes_priority_for_duplicates(self):
        det = [_issue(endpoint="GET /test", description="det description")]
        agentic = [_issue(endpoint="GET /test", description="agentic description", source="security_analyst")]

        result = self.orchestrator._merge_issues(agentic, det)
        assert len(result) == 1
        assert result[0].description == "agentic description"
        assert result[0].source == "security_analyst"

    def test_deterministic_fills_gaps(self):
        det = [
            _issue(endpoint="GET /a", description="det A"),
            _issue(endpoint="GET /b", description="det B"),
            _issue(endpoint="GET /c", description="det C"),
        ]
        agentic = [
            _issue(endpoint="GET /a", description="agentic A", source="security_analyst"),
        ]

        result = self.orchestrator._merge_issues(agentic, det)
        assert len(result) == 3
        by_ep = {i.endpoint: i for i in result}
        assert by_ep["GET /a"].description == "agentic A"
        assert by_ep["GET /b"].description == "det B"
        assert by_ep["GET /c"].description == "det C"

    def test_deterministic_issues_tagged_with_source(self):
        det = [_issue(endpoint="GET /a", source=None)]
        agentic: list[Issue] = []

        result = self.orchestrator._merge_issues(agentic, det)
        assert result[0].source == "deterministic_rule_engine"

    def test_deterministic_issues_keep_existing_source(self):
        det = [_issue(endpoint="GET /a", source="rule_missing_auth")]
        agentic: list[Issue] = []

        result = self.orchestrator._merge_issues(agentic, det)
        assert result[0].source == "rule_missing_auth"

    def test_different_types_same_endpoint_not_merged(self):
        det = [_issue(issue_type="missing_auth", endpoint="GET /test")]
        agentic = [_issue(issue_type="missing_validation", endpoint="GET /test", source="quality_analyst")]

        result = self.orchestrator._merge_issues(agentic, det)
        assert len(result) == 2

    def test_different_services_same_type_not_merged(self):
        det = [_issue(service="svc-a", endpoint="GET /test")]
        agentic = [_issue(service="svc-b", endpoint="GET /test", source="security_analyst")]

        result = self.orchestrator._merge_issues(agentic, det)
        assert len(result) == 2

    def test_empty_both(self):
        result = self.orchestrator._merge_issues([], [])
        assert result == []
