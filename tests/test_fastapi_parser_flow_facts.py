from __future__ import annotations

import tempfile
import textwrap
import unittest
from pathlib import Path

from src.analyzers.fastapi.parser import FastAPIParser


class FastAPIParserFlowFactsTest(unittest.TestCase):
    def test_parser_collects_router_dependency_wrappers_and_global_facts(self) -> None:
        source = textwrap.dedent(
            """
            from fastapi import FastAPI, APIRouter, Depends, Request
            from pydantic import BaseModel

            app = FastAPI()
            router = APIRouter(prefix="/secure", dependencies=[Depends(get_current_user)])

            class CreateRequest(BaseModel):
                name: str

            class CreateResponse(BaseModel):
                id: int

            def get_current_user():
                return {"user": "ok"}

            def require_admin():
                return True

            @router.post("/orders", response_model=CreateResponse)
            @require_admin()
            async def create_order(payload: CreateRequest):
                logger.info("audit")
                return CreateResponse(id=1)

            app.include_router(router, dependencies=[Depends(require_admin)])

            @app.middleware("http")
            async def trace_middleware(request: Request, call_next):
                return await call_next(request)

            @app.exception_handler(Exception)
            async def global_handler(request: Request, exc: Exception):
                return {"detail": "error"}
            """
        )

        with tempfile.TemporaryDirectory() as tmpdir:
            repo_path = Path(tmpdir)
            module_path = repo_path / "app.py"
            module_path.write_text(source, encoding="utf-8")

            result = FastAPIParser().parse("service-a", repo_path)

        self.assertEqual(len(result.backend_endpoints), 1)
        endpoint = result.backend_endpoints[0]

        self.assertEqual(endpoint.path, "/secure/orders")
        self.assertEqual(endpoint.method, "POST")
        self.assertEqual(endpoint.request_schema, "CreateRequest")
        self.assertEqual(endpoint.response_schema, "CreateResponse")

        self.assertTrue(any("get_current_user" in dep for dep in endpoint.dependencies))
        self.assertTrue(any("require_admin" in dep for dep in endpoint.dependencies))
        self.assertIn("require_admin", endpoint.decorators)
        self.assertIn("logger.info", endpoint.call_refs)
        self.assertIn("audit", [value.lower() for value in endpoint.string_refs])

        self.assertIn("trace_middleware", result.fastapi_facts.middleware_refs)
        self.assertIn("exception_handler", result.fastapi_facts.exception_handler_refs)
        self.assertTrue(any("depends" in dep.lower() or "current_user" in dep.lower() for dep in result.fastapi_facts.global_dependencies))


if __name__ == "__main__":
    unittest.main()
