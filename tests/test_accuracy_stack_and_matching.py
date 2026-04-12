from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from src.schemas.internal import (
    AuthMiddlewareAnalysisResult,
    BackendEndpoint,
    FastAPIGlobalFacts,
    FrontendCall,
    StaticAnalysisResult,
)
from src.standards.coverage_tracker import EndpointCoverageTracker
from src.standards.evidence_collectors.auth_evidence import collect_auth_evidence
from src.standards.evidence_collectors.backend_evidence import (
    collect_response_contract_evidence,
    collect_validation_evidence,
)
from src.standards.evidence_collectors.generic_evidence import (
    RepoCodeIndex,
    collect_generic_fastapi_category,
    detect_conflicting_style,
)
from src.standards.resolver import CategoryResolution, ResolvedStandard, StackResolution
from src.utils.canonicalization import canonicalize_frontend_url_path, classify_auth_mode


class AccuracyStackAndMatchingTest(unittest.TestCase):
    def _resolved_standard(self) -> ResolvedStandard:
        resolved = ResolvedStandard(standard_id="std", name="Standard")
        resolved.fastapi.categories["auth_mechanism"] = CategoryResolution(
            category_id="auth_mechanism",
            selected_style="jwt_bearer",
            check_strategy="jwt_mechanism",
            evidence_markers=["jwt.decode", "Bearer"],
            label="JWT",
        )
        resolved.fastapi.categories["request_validation"] = CategoryResolution(
            category_id="request_validation",
            selected_style="pydantic_models",
            check_strategy="pydantic_validation",
            evidence_markers=["BaseModel"],
            label="Pydantic",
        )
        resolved.react.categories["http_client"] = CategoryResolution(
            category_id="http_client",
            selected_style="axios",
            check_strategy="axios_http",
            evidence_markers=["axios"],
            label="Axios",
        )
        return resolved

    def test_canonicalize_frontend_template_url_with_query_suffix(self) -> None:
        raw = "${BASE_PATH}/admin/material-jobs${query}"
        self.assertEqual(
            canonicalize_frontend_url_path(raw),
            "/admin/material-jobs",
        )

    def test_auth_mode_not_contaminated_by_module_level_service_markers(self) -> None:
        endpoint = BackendEndpoint(
            service="svc",
            file="src/api/routes.py",
            path="/secure/profile",
            method="GET",
            dependencies=["user:get_current_user"],
        )
        facts = FastAPIGlobalFacts(module_call_refs=["require_service_token", "x-service-token"])
        mode = classify_auth_mode(endpoint, facts)
        self.assertEqual(mode, "user_auth")

    def test_generic_auth_mechanism_uses_dependency_chain_marker_hits(self) -> None:
        resolved = self._resolved_standard()
        endpoint = BackendEndpoint(
            service="svc",
            file="src/api/routes.py",
            path="/secure/me",
            method="GET",
            dependencies=["current_user:get_current_user"],
            call_refs=["Depends"],
            route_intent="business_endpoint",
            auth_mode="user_auth",
        )
        static = StaticAnalysisResult(repo="svc", backend_endpoints=[endpoint])

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "src" / "api").mkdir(parents=True, exist_ok=True)
            (root / "src" / "api" / "routes.py").write_text(
                "from fastapi import Depends\n"
                "async def me(current_user=Depends(get_current_user)):\n"
                "    return current_user\n",
                encoding="utf-8",
            )
            (root / "src" / "api" / "dependencies.py").write_text(
                "import jwt\n"
                "def get_current_user(token: str):\n"
                "    return jwt.decode(token, 'secret', algorithms=['HS256'])\n",
                encoding="utf-8",
            )

            repo_index = RepoCodeIndex({"svc": tmpdir})
            result = collect_generic_fastapi_category(
                resolved,
                {"svc": static},
                "auth_mechanism",
                repo_index,
            )

        self.assertEqual(result.category, "auth_mechanism")
        violations = [item for item in result.evidence_items if item.status == "violation"]
        self.assertEqual(len(violations), 0)
        self.assertTrue(any(item.status == "compliant" for item in result.evidence_items))

    def test_coverage_matrix_respects_repo_stack_type(self) -> None:
        resolved = self._resolved_standard()
        tracker = EndpointCoverageTracker(resolved)

        backend_static = StaticAnalysisResult(
            repo="backend_repo",
            backend_endpoints=[
                BackendEndpoint(
                    service="backend_repo",
                    file="src/api/routes.py",
                    path="/items",
                    method="POST",
                )
            ],
        )
        frontend_static = StaticAnalysisResult(
            repo="frontend_repo",
            frontend_calls=[
                FrontendCall(
                    service="frontend_repo",
                    file="src/features/items/api.ts",
                    line=10,
                    raw_url="/items",
                    method="GET",
                )
            ],
        )

        tracker.build_matrix(
            {
                "backend_repo": backend_static,
                "frontend_repo": frontend_static,
            },
            repo_types={
                "backend_repo": "backend",
                "frontend_repo": "frontend",
            },
        )
        matrix = tracker.get_matrix()

        self.assertFalse(
            any(cell.stack == "fastapi" and cell.service == "frontend_repo" for cell in matrix.cells)
        )
        self.assertFalse(
            any(cell.stack == "react" and cell.service == "backend_repo" for cell in matrix.cells)
        )

    def test_backend_collectors_use_strategy_for_pydantic_and_response_model(self) -> None:
        resolved = ResolvedStandard(standard_id="std", name="Standard")
        resolved.fastapi.categories["request_validation"] = CategoryResolution(
            category_id="request_validation",
            selected_style="pydantic_models",
            check_strategy="pydantic_validation",
            evidence_markers=["BaseModel"],
        )
        resolved.fastapi.categories["response_contract"] = CategoryResolution(
            category_id="response_contract",
            selected_style="response_model",
            check_strategy="response_model_contract",
            evidence_markers=["response_model="],
        )
        static = StaticAnalysisResult(
            repo="svc",
            backend_endpoints=[
                BackendEndpoint(
                    service="svc",
                    file="src/api/routes.py",
                    path="/items",
                    method="POST",
                    request_schema="CreateItemRequest",
                    response_schema="CreateItemResponse",
                )
            ],
        )

        validation = collect_validation_evidence(resolved, {"svc": static})
        contracts = collect_response_contract_evidence(resolved, {"svc": static})

        self.assertEqual(validation.overall_status, "compliant")
        self.assertEqual(contracts.overall_status, "compliant")


    def test_di_auth_violation_when_middleware_does_real_auth(self) -> None:
        """When standard says dependency_injection but repo has JWT middleware,
        all protected endpoints must be flagged as violations."""
        resolved = ResolvedStandard(standard_id="std", name="Standard")
        resolved.fastapi = StackResolution(stack_type="fastapi")
        resolved.fastapi.categories["auth_style"] = CategoryResolution(
            category_id="auth_style",
            selected_style="dependency_injection",
            check_strategy="dep_injection_auth",
            evidence_markers=["Depends(", "get_current_user", "Security("],
        )

        mw_analysis = AuthMiddlewareAnalysisResult(
            middleware_name="JWTMiddleware",
            mechanism="jwt_bearer",
            public_paths=["/health", "/docs"],
            sets_request_state=True,
        )
        facts = FastAPIGlobalFacts(
            middleware_refs=["JWTMiddleware"],
            auth_middleware_analysis=mw_analysis,
        )
        endpoints = [
            BackendEndpoint(
                service="ticket_svc",
                file="src/api/rest/routes/tickets.py",
                line=42,
                path="/tickets",
                method="GET",
                dependencies=["user_id:get_current_user_id"],
            ),
            BackendEndpoint(
                service="ticket_svc",
                file="src/api/rest/routes/tickets.py",
                line=80,
                path="/tickets/{ticket_id}",
                method="PUT",
                dependencies=["user_id:get_current_user_id", "role:get_current_user_role"],
            ),
        ]
        static = StaticAnalysisResult(
            repo="ticket_svc",
            backend_endpoints=endpoints,
            fastapi_facts=facts,
        )

        result = collect_auth_evidence(resolved, {"ticket_svc": static})

        violations = [e for e in result.evidence_items if e.status == "violation"]
        compliant = [e for e in result.evidence_items if e.status == "compliant"]
        self.assertGreater(len(violations), 0, "Middleware-based auth should violate DI standard")
        self.assertEqual(len(compliant), 0, "No endpoints should be compliant")
        self.assertTrue(
            any("middleware" in v.message.lower() for v in violations),
            "Violation message should mention middleware",
        )

    def test_di_auth_pass_when_no_middleware_and_real_di(self) -> None:
        """When standard says dependency_injection and repo has no middleware,
        endpoints with HTTPBearer/Security deps should be compliant."""
        resolved = ResolvedStandard(standard_id="std", name="Standard")
        resolved.fastapi = StackResolution(stack_type="fastapi")
        resolved.fastapi.categories["auth_style"] = CategoryResolution(
            category_id="auth_style",
            selected_style="dependency_injection",
            check_strategy="dep_injection_auth",
            evidence_markers=["Depends(", "get_current_user", "Security("],
        )

        facts = FastAPIGlobalFacts(middleware_refs=[])
        endpoints = [
            BackendEndpoint(
                service="auth_svc",
                file="src/api/rest/routes/auth.py",
                line=30,
                path="/me",
                method="GET",
                dependencies=["current_user:get_current_active_user"],
                dep_classifications=["auth:jwt_bearer"],
            ),
        ]
        static = StaticAnalysisResult(
            repo="auth_svc",
            backend_endpoints=endpoints,
            fastapi_facts=facts,
        )

        result = collect_auth_evidence(resolved, {"auth_svc": static})

        compliant = [e for e in result.evidence_items if e.status == "compliant"]
        self.assertGreater(len(compliant), 0, "Real DI auth should be compliant")

    def test_conflict_detection_finds_conflicting_style(self) -> None:
        """detect_conflicting_style should find markers from non-selected options."""
        category = CategoryResolution(
            category_id="auth_style",
            selected_style="dependency_injection",
            check_strategy="dep_injection_auth",
            evidence_markers=["Depends(", "get_current_user"],
            other_options={
                "global_middleware": ["add_middleware", "JWTMiddleware", "AuthMiddleware"],
                "decorator": ["@require_auth", "@login_required"],
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "src" / "api").mkdir(parents=True, exist_ok=True)
            (root / "src" / "api" / "app.py").write_text(
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "app.add_middleware(JWTMiddleware)\n",
                encoding="utf-8",
            )
            repo_index = RepoCodeIndex({"svc": tmpdir})
            result = detect_conflicting_style(category, repo_index, "svc", "fastapi")

        self.assertIsNotNone(result, "Should detect conflicting middleware markers")
        style, hits = result
        self.assertEqual(style, "global_middleware")
        self.assertTrue(any("JWTMiddleware" in h.marker for h in hits))

    def test_no_conflict_when_selected_style_is_correct(self) -> None:
        """detect_conflicting_style should return None when no other style markers found."""
        category = CategoryResolution(
            category_id="auth_style",
            selected_style="global_middleware",
            check_strategy="middleware_auth",
            evidence_markers=["add_middleware", "JWTMiddleware"],
            other_options={
                "dependency_injection": ["HTTPBearer", "Security(", "oauth2_scheme"],
            },
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            root = Path(tmpdir)
            (root / "src" / "api").mkdir(parents=True, exist_ok=True)
            (root / "src" / "api" / "app.py").write_text(
                "from fastapi import FastAPI\n"
                "app = FastAPI()\n"
                "app.add_middleware(JWTMiddleware)\n",
                encoding="utf-8",
            )
            repo_index = RepoCodeIndex({"svc": tmpdir})
            result = detect_conflicting_style(category, repo_index, "svc", "fastapi")

        self.assertIsNone(result, "No conflict when project matches selected style")


if __name__ == "__main__":
    unittest.main()
