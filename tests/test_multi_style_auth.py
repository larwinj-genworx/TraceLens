"""Tests for multi-style auth detection, Annotated deps parsing, and scoring formula."""
from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from src.analyzers.fastapi.parser import FastAPIParser
from src.control.agents.orchestrator import ValidationOrchestrator
from src.flows.analyzer import MandatoryFlowAnalyzer
from src.schemas.internal import (
    BackendEndpoint,
    FastAPIGlobalFacts,
    FlowStatus,
    StaticAnalysisResult,
)
from src.schemas.issues import Issue, Severity


# ── Middleware auth detection in flow analyzer ────────────────────────────────


class TestDetectAuthMiddleware(unittest.TestCase):
    def setUp(self):
        self.analyzer = MandatoryFlowAnalyzer()

    def test_jwt_middleware_detected(self):
        result = self.analyzer._detect_auth_middleware(["JWTMiddleware", "StructLogMiddleware"])
        self.assertEqual(result, ["JWTMiddleware"])

    def test_auth_middleware_detected(self):
        result = self.analyzer._detect_auth_middleware(["AuthMiddleware", "CORSMiddleware"])
        self.assertEqual(result, ["AuthMiddleware"])

    def test_bearer_token_middleware(self):
        result = self.analyzer._detect_auth_middleware(["BearerTokenMiddleware"])
        self.assertEqual(result, ["BearerTokenMiddleware"])

    def test_session_middleware(self):
        result = self.analyzer._detect_auth_middleware(["SessionMiddleware"])
        self.assertEqual(result, ["SessionMiddleware"])

    def test_oauth_middleware(self):
        result = self.analyzer._detect_auth_middleware(["OAuth2Middleware"])
        self.assertEqual(result, ["OAuth2Middleware"])

    def test_non_auth_middleware_ignored(self):
        result = self.analyzer._detect_auth_middleware(
            ["CORSMiddleware", "StructLogMiddleware", "GZipMiddleware"]
        )
        self.assertEqual(result, [])

    def test_empty_list(self):
        result = self.analyzer._detect_auth_middleware([])
        self.assertEqual(result, [])

    def test_multiple_auth_middleware(self):
        result = self.analyzer._detect_auth_middleware(
            ["JWTMiddleware", "SessionMiddleware", "CORSMiddleware"]
        )
        self.assertIn("JWTMiddleware", result)
        self.assertIn("SessionMiddleware", result)
        self.assertEqual(len(result), 2)


class TestMiddlewareAuthInFlowAnalyzer(unittest.TestCase):
    """Endpoints behind auth middleware should be marked COVERED for authn_flow."""

    def test_middleware_auth_marks_endpoint_covered(self):
        static_results = {
            "ticket_svc": StaticAnalysisResult(
                repo="ticket_svc",
                backend_endpoints=[
                    BackendEndpoint(
                        service="ticket_svc",
                        file="routes/sla.py",
                        line=10,
                        path="/sla-rules",
                        method="GET",
                        dependencies=[],
                    )
                ],
                fastapi_facts=FastAPIGlobalFacts(
                    middleware_refs=["JWTMiddleware", "add_middleware"],
                ),
            )
        }

        result = MandatoryFlowAnalyzer().evaluate(static_results)
        authn_items = [i for i in result.flow_coverage if i.flow_id == "authn_flow"]
        self.assertEqual(len(authn_items), 1)
        self.assertEqual(authn_items[0].status, FlowStatus.COVERED)
        self.assertEqual(authn_items[0].evidence.get("covered_by"), "middleware")

    def test_no_middleware_no_deps_marks_missing(self):
        static_results = {
            "bare_svc": StaticAnalysisResult(
                repo="bare_svc",
                backend_endpoints=[
                    BackendEndpoint(
                        service="bare_svc",
                        file="routes/api.py",
                        line=5,
                        path="/items",
                        method="GET",
                        dependencies=[],
                    )
                ],
                fastapi_facts=FastAPIGlobalFacts(
                    middleware_refs=["CORSMiddleware"],
                ),
            )
        }

        result = MandatoryFlowAnalyzer().evaluate(static_results)
        authn_items = [i for i in result.flow_coverage if i.flow_id == "authn_flow"]
        self.assertEqual(len(authn_items), 1)
        self.assertEqual(authn_items[0].status, FlowStatus.MISSING)

    def test_deps_take_priority_over_middleware(self):
        static_results = {
            "svc": StaticAnalysisResult(
                repo="svc",
                backend_endpoints=[
                    BackendEndpoint(
                        service="svc",
                        file="routes/api.py",
                        line=5,
                        path="/secure",
                        method="GET",
                        dependencies=["user:get_current_user"],
                    )
                ],
                fastapi_facts=FastAPIGlobalFacts(
                    middleware_refs=["JWTMiddleware"],
                ),
            )
        }

        result = MandatoryFlowAnalyzer().evaluate(static_results)
        authn_items = [i for i in result.flow_coverage if i.flow_id == "authn_flow"]
        self.assertEqual(len(authn_items), 1)
        self.assertEqual(authn_items[0].status, FlowStatus.COVERED)
        self.assertIsInstance(authn_items[0].evidence.get("covered_by"), list)


class TestDecoratorDepsDetected(unittest.TestCase):
    """Dependencies from route decorator/router (no colon prefix) should be detected."""

    def test_decorator_level_auth_dep_detected(self):
        static_results = {
            "svc": StaticAnalysisResult(
                repo="svc",
                backend_endpoints=[
                    BackendEndpoint(
                        service="svc",
                        file="routes.py",
                        line=10,
                        path="/admin/teams",
                        method="POST",
                        dependencies=["require_auth"],
                    )
                ],
            )
        }

        result = MandatoryFlowAnalyzer().evaluate(static_results)
        authn_items = [i for i in result.flow_coverage if i.flow_id == "authn_flow"]
        self.assertEqual(len(authn_items), 1)
        self.assertEqual(authn_items[0].status, FlowStatus.COVERED)


# ── Annotated deps parsing ────────────────────────────────────────────────────


class TestAnnotatedDepsExtraction(unittest.TestCase):
    def test_direct_annotated_depends(self):
        source = textwrap.dedent("""\
            from typing import Annotated
            from fastapi import FastAPI, Depends

            app = FastAPI()

            def get_current_user():
                return {"user": "test"}

            @app.get("/profile")
            async def profile(user: Annotated[dict, Depends(get_current_user)]):
                return user
        """)

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            (repo_path / "main.py").write_text(source)
            result, _file_asts = FastAPIParser().parse("svc", repo_path)

        self.assertEqual(len(result.backend_endpoints), 1)
        ep = result.backend_endpoints[0]
        self.assertTrue(
            any("get_current_user" in dep for dep in ep.dependencies),
            f"Expected get_current_user in deps, got {ep.dependencies}",
        )

    def test_type_alias_annotated_depends(self):
        source = textwrap.dedent("""\
            from typing import Annotated
            from fastapi import FastAPI, Depends

            app = FastAPI()

            def get_db():
                return "db_session"

            def get_current_user_id():
                return "user123"

            DBSession = Annotated[str, Depends(get_db)]
            CurrentUserID = Annotated[str, Depends(get_current_user_id)]

            @app.get("/items")
            async def list_items(db: DBSession, user_id: CurrentUserID):
                return []
        """)

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            (repo_path / "main.py").write_text(source)
            result, _file_asts = FastAPIParser().parse("svc", repo_path)

        self.assertEqual(len(result.backend_endpoints), 1)
        ep = result.backend_endpoints[0]
        dep_names = " ".join(ep.dependencies)
        self.assertIn("get_db", dep_names)
        self.assertIn("get_current_user_id", dep_names)

    def test_cross_file_type_alias(self):
        deps_source = textwrap.dedent("""\
            from typing import Annotated
            from fastapi import Depends

            def get_current_user():
                return "user"

            CurrentUser = Annotated[str, Depends(get_current_user)]
        """)

        routes_source = textwrap.dedent("""\
            from fastapi import APIRouter
            from deps import CurrentUser

            router = APIRouter()

            @router.get("/me")
            async def get_me(user: CurrentUser):
                return user
        """)

        app_source = textwrap.dedent("""\
            from fastapi import FastAPI
            from routes import router

            app = FastAPI()
            app.include_router(router)
        """)

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            (repo_path / "deps.py").write_text(deps_source)
            (repo_path / "routes.py").write_text(routes_source)
            (repo_path / "app.py").write_text(app_source)
            result, _file_asts = FastAPIParser().parse("svc", repo_path)

        endpoints = [ep for ep in result.backend_endpoints if ep.path == "/me"]
        self.assertEqual(len(endpoints), 1)
        dep_names = " ".join(endpoints[0].dependencies)
        self.assertIn("get_current_user", dep_names)

    def test_old_style_still_works(self):
        source = textwrap.dedent("""\
            from fastapi import FastAPI, Depends

            app = FastAPI()

            def get_db():
                return "db"

            @app.get("/old")
            async def old_style(db=Depends(get_db)):
                return db
        """)

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            (repo_path / "main.py").write_text(source)
            result, _file_asts = FastAPIParser().parse("svc", repo_path)

        self.assertEqual(len(result.backend_endpoints), 1)
        ep = result.backend_endpoints[0]
        self.assertTrue(any("get_db" in dep for dep in ep.dependencies))


# ── Scoring formula ───────────────────────────────────────────────────────────


class TestScoringFormula(unittest.TestCase):
    def setUp(self):
        self.orchestrator = ValidationOrchestrator()

    def _issue(self, severity: Severity) -> Issue:
        return Issue(
            type="test",
            severity=severity,
            service="svc",
            description="desc",
            impact="impact",
            fix="fix",
        )

    def test_zero_issues_gives_100(self):
        summary = self.orchestrator._build_summary([])
        self.assertEqual(summary.score, 100)

    def test_single_critical_meaningful_score(self):
        issues = [self._issue(Severity.CRITICAL)]
        summary = self.orchestrator._build_summary(issues)
        self.assertGreater(summary.score, 0)
        self.assertLess(summary.score, 100)

    def test_six_criticals_nonzero(self):
        issues = [self._issue(Severity.CRITICAL) for _ in range(6)]
        summary = self.orchestrator._build_summary(issues)
        self.assertGreater(summary.score, 0)

    def test_sixteen_criticals_nonzero(self):
        issues = [self._issue(Severity.CRITICAL) for _ in range(16)]
        summary = self.orchestrator._build_summary(issues)
        self.assertGreater(summary.score, 0)
        self.assertLessEqual(summary.score, 30)

    def test_score_decreases_with_more_issues(self):
        score_3 = self.orchestrator._build_summary(
            [self._issue(Severity.CRITICAL) for _ in range(3)]
        ).score
        score_6 = self.orchestrator._build_summary(
            [self._issue(Severity.CRITICAL) for _ in range(6)]
        ).score
        score_16 = self.orchestrator._build_summary(
            [self._issue(Severity.CRITICAL) for _ in range(16)]
        ).score
        self.assertGreater(score_3, score_6)
        self.assertGreater(score_6, score_16)

    def test_score_within_bounds(self):
        issues = (
            [self._issue(Severity.CRITICAL) for _ in range(50)]
            + [self._issue(Severity.HIGH) for _ in range(20)]
            + [self._issue(Severity.MEDIUM) for _ in range(100)]
        )
        summary = self.orchestrator._build_summary(issues)
        self.assertGreaterEqual(summary.score, 0)
        self.assertLessEqual(summary.score, 100)

    def test_severity_weights_respected(self):
        crit_score = self.orchestrator._build_summary(
            [self._issue(Severity.CRITICAL)]
        ).score
        high_score = self.orchestrator._build_summary(
            [self._issue(Severity.HIGH)]
        ).score
        med_score = self.orchestrator._build_summary(
            [self._issue(Severity.MEDIUM)]
        ).score
        self.assertLess(crit_score, high_score)
        self.assertLess(high_score, med_score)


if __name__ == "__main__":
    unittest.main()
