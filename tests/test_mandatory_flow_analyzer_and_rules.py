from __future__ import annotations

import unittest

from src.flows.analyzer import MandatoryFlowAnalyzer
from src.flows.catalog import FlowCatalogLoader
from src.rules.engine import RuleEngine
from src.schemas.internal import (
    AnalysisContext,
    BackendEndpoint,
    EnvInferenceResult,
    FlowCoverageItem,
    FlowStatus,
    GraphBuildResult,
    Observation,
    StaticAnalysisResult,
)


class MandatoryFlowAnalyzerAndRulesTest(unittest.TestCase):
    def test_analyzer_emits_ambiguous_observation_for_identity_style_auth(self) -> None:
        static_results = {
            "svc": StaticAnalysisResult(
                repo="svc",
                backend_endpoints=[
                    BackendEndpoint(
                        service="svc",
                        file="app/routes.py",
                        line=18,
                        path="/secure/profile",
                        method="GET",
                        dependencies=["identity_context"],
                        call_refs=["resolve_identity"],
                    )
                ],
            )
        }

        result = MandatoryFlowAnalyzer().evaluate(static_results)

        authn_items = [item for item in result.flow_coverage if item.flow_id == "authn_flow"]
        self.assertEqual(len(authn_items), 1)
        self.assertEqual(authn_items[0].status, FlowStatus.AMBIGUOUS)

        observation_flows = {item.flow_id for item in result.observations}
        self.assertIn("authn_flow", observation_flows)

    def test_rule_engine_generates_issues_only_for_missing_flow_status(self) -> None:
        catalog = FlowCatalogLoader().load()
        definitions = {flow.id: flow for flow in catalog.flows}

        coverage = [
            FlowCoverageItem(
                flow_id="authn_flow",
                service="svc",
                endpoint="POST /secure/orders",
                status=FlowStatus.MISSING,
                confidence=0.9,
                evidence={"covered_hits": []},
            ),
            FlowCoverageItem(
                flow_id="request_validation_flow",
                service="svc",
                endpoint="POST /secure/orders",
                status=FlowStatus.MISSING,
                confidence=0.85,
                evidence={"request_schema": None},
            ),
            FlowCoverageItem(
                flow_id="rate_limit_flow",
                service="svc",
                endpoint="POST /login",
                status=FlowStatus.MISSING,
                confidence=0.84,
                evidence={"covered_hits": []},
            ),
            FlowCoverageItem(
                flow_id="authz_flow",
                service="svc",
                endpoint="POST /secure/orders",
                status=FlowStatus.AMBIGUOUS,
                confidence=0.58,
                evidence={"ambiguous_hits": ["admin"]},
            ),
        ]

        context = AnalysisContext(
            repos=[],
            static_results={},
            env_result=EnvInferenceResult(),
            graph_result=GraphBuildResult(),
            flow_catalog_version=catalog.version,
            flow_definitions=definitions,
            flow_coverage=coverage,
            observations=[
                Observation(
                    flow_id="authz_flow",
                    service="svc",
                    endpoint="POST /secure/orders",
                    message="Authorization markers are ambiguous.",
                    confidence=0.58,
                )
            ],
        )

        issues = RuleEngine().evaluate(context)
        issue_types = {item.type for item in issues}

        self.assertIn("missing_auth", issue_types)
        self.assertIn("missing_validation", issue_types)
        self.assertIn("missing_rate_limit_flow", issue_types)
        self.assertNotIn("missing_authz_flow", issue_types)


if __name__ == "__main__":
    unittest.main()
