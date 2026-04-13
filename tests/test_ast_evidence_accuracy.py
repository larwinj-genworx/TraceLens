"""Regression tests for AST-based evidence accuracy.

Each test creates a minimal Python source string that previously caused
false positives under the old substring-matching system, parses it with
``ast.parse``, builds an ``ASTCodeIndex``, and verifies that the structured
markers produce zero false-positive hits.
"""

from __future__ import annotations

import ast
import textwrap
from pathlib import Path

import pytest

from src.standards.evidence_collectors.ast_code_index import (
    ASTCodeIndex,
    ASTHit,
    resolve_marker_hits,
)


def _build_index_from_source(source: str, service: str = "test_svc") -> ASTCodeIndex:
    """Helper: build an ASTCodeIndex from a single source string."""
    tmp = Path("/tmp/_ast_test_file.py")
    tmp.write_text(textwrap.dedent(source), encoding="utf-8")
    tree = ast.parse(textwrap.dedent(source))
    file_asts = {"_test_file": (tmp, tree)}
    return ASTCodeIndex.build_multi({service: file_asts}, {service: "/tmp"})


# ─── authz_enforcement / service_layer_check ──────────────────────────────

SERVICE_LAYER_MARKERS = [
    {"type": "call", "name": "authorize"},
    {"type": "call", "name": "check_access"},
    {"type": "call", "name": "verify_permission"},
    {"type": "call", "name": "can_access"},
]


class TestAuthzEnforcementFalsePositives:
    def test_unauthorized_constant_not_matched(self):
        """HTTP_401_UNAUTHORIZED must not trigger service_layer_check."""
        source = """
        from starlette import status
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid token payload."
        )
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", SERVICE_LAYER_MARKERS)
        assert len(hits) == 0, f"False positive hits: {[h.excerpt for h in hits]}"

    def test_authorization_header_param_not_matched(self):
        """Parameter named 'authorization' must not trigger."""
        source = """
        from fastapi import Header
        async def get_user(authorization: str = Header(...)):
            pass
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", SERVICE_LAYER_MARKERS)
        assert len(hits) == 0, f"False positive hits: {[h.excerpt for h in hits]}"

    def test_actual_authorize_call_matched(self):
        """A real authorize() call should be detected."""
        source = """
        def handle_request(user):
            authorize(user, "admin")
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", SERVICE_LAYER_MARKERS)
        assert len(hits) >= 1


# ─── database_orm / tortoise_orm ──────────────────────────────────────────

TORTOISE_MARKERS = [
    {"type": "import", "name": "tortoise", "from_module": "tortoise"},
    {"type": "base_class", "name": "Model", "exclude": ["BaseModel", "BaseSettings"]},
    {"type": "import", "name": "fields", "from_module": "tortoise"},
]


class TestDatabaseOrmFalsePositives:
    def test_basemodel_not_matched_as_tortoise_model(self):
        """Pydantic BaseModel inheritance must not trigger tortoise_orm."""
        source = """
        from pydantic import BaseModel

        class UserCreate(BaseModel):
            username: str
            email: str
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", TORTOISE_MARKERS)
        assert len(hits) == 0, f"False positive hits: {[h.excerpt for h in hits]}"

    def test_actual_tortoise_model_matched(self):
        """A real Tortoise ORM Model should be detected."""
        source = """
        from tortoise import fields, Model

        class User(Model):
            id = fields.IntField(pk=True)
            name = fields.CharField(max_length=255)
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", TORTOISE_MARKERS)
        assert len(hits) >= 1


# ─── database_orm / sqlalchemy_sync ───────────────────────────────────────

SQLALCHEMY_MARKERS = [
    {"type": "import", "name": "sqlalchemy", "from_module": "sqlalchemy"},
    {"type": "import", "name": "Session", "from_module": "sqlalchemy"},
    {"type": "import", "name": "create_engine", "from_module": "sqlalchemy"},
    {"type": "import", "name": "sessionmaker", "from_module": "sqlalchemy"},
    {"type": "call", "name": "sessionmaker"},
    {"type": "call", "name": "create_engine"},
]


class TestSqlalchemySyncFalsePositives:
    def test_session_id_field_not_matched(self):
        """Field named session_id must not trigger sqlalchemy_sync."""
        source = """
        from pydantic import BaseModel

        class TokenPayload(BaseModel):
            session_id: str
            user_id: int
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", SQLALCHEMY_MARKERS)
        assert len(hits) == 0, f"False positive hits: {[h.excerpt for h in hits]}"

    def test_actual_sqlalchemy_import_matched(self):
        """Real SQLAlchemy imports should be detected."""
        source = """
        from sqlalchemy import create_engine
        from sqlalchemy.orm import Session, sessionmaker
        engine = create_engine("sqlite:///test.db")
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", SQLALCHEMY_MARKERS)
        assert len(hits) >= 1


# ─── api_architecture / graphql ───────────────────────────────────────────

GRAPHQL_MARKERS = [
    {"type": "import", "name": "graphene", "from_module": "graphene"},
    {"type": "import", "name": "strawberry", "from_module": "strawberry"},
    {"type": "import", "name": "ariadne", "from_module": "ariadne"},
    {"type": "base_class", "name": "Query", "exclude": ["BaseModel"]},
    {"type": "base_class", "name": "Mutation", "exclude": ["BaseModel"]},
    {"type": "call", "name": "graphql"},
]


class TestApiArchitectureFalsePositives:
    def test_query_variable_not_matched(self):
        """SQL query variable or FastAPI Query() must not trigger graphql."""
        source = """
        from fastapi import Query

        async def search(query: str = Query(...)):
            result = db.execute(query)
            return result
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", GRAPHQL_MARKERS)
        assert len(hits) == 0, f"False positive hits: {[h.excerpt for h in hits]}"

    def test_actual_graphql_import_matched(self):
        """Real graphene import should be detected."""
        source = """
        import graphene

        class UserQuery(graphene.ObjectType):
            users = graphene.List(UserType)
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", GRAPHQL_MARKERS)
        assert len(hits) >= 1


# ─── api_versioning / query_param ─────────────────────────────────────────

QUERY_PARAM_MARKERS = [
    {"type": "string_literal", "pattern": "\\?version=|\\?v="},
    {"type": "keyword_arg", "name": "version", "in_call": "params"},
    {"type": "call", "name": "api_version"},
]


class TestApiVersioningFalsePositives:
    def test_version_kwarg_in_fastapi_not_matched(self):
        """version= kwarg in FastAPI() constructor must not trigger query_param."""
        source = """
        from fastapi import FastAPI

        _SERVICE_VERSION = "1.0.0"
        app = FastAPI(title="MyApp", version=_SERVICE_VERSION)
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", QUERY_PARAM_MARKERS)
        assert len(hits) == 0, f"False positive hits: {[h.excerpt for h in hits]}"


# ─── di_style / manual_constructor ────────────────────────────────────────

MANUAL_DI_MARKERS = [
    {"type": "call", "name": "inject"},
    {"type": "import", "name": "inject", "from_module": "inject"},
    {"type": "decorator", "name": "inject"},
]


class TestDiStyleFalsePositives:
    def test_regular_init_not_matched(self):
        """Regular __init__ must not trigger manual_constructor DI style."""
        source = """
        class UserService:
            def __init__(self):
                self.db = None
                self.cache = {}
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", MANUAL_DI_MARKERS)
        assert len(hits) == 0, f"False positive hits: {[h.excerpt for h in hits]}"

    def test_self_dot_not_matched(self):
        """self.attribute access must not trigger manual_constructor DI style."""
        source = """
        class Service:
            def process(self):
                return self.repository.get_all()
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", MANUAL_DI_MARKERS)
        assert len(hits) == 0, f"False positive hits: {[h.excerpt for h in hits]}"


# ─── input_sanitization / custom_sanitizer ────────────────────────────────

CUSTOM_SANITIZER_MARKERS = [
    {"type": "call", "name": "sanitize"},
    {"type": "call", "name": "strip_tags"},
    {"type": "call", "name": "clean_html"},
    {"type": "call", "name": "escape", "exclude_modules": ["xml.sax", "markupsafe", "html"]},
]


class TestInputSanitizationFalsePositives:
    def test_xml_escape_import_not_matched(self):
        """xml.sax escape import must not trigger custom_sanitizer."""
        source = """
        from xml.sax.saxutils import escape

        def render_xml(text):
            return escape(text)
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", CUSTOM_SANITIZER_MARKERS)
        assert len(hits) == 0, f"False positive hits: {[h.excerpt for h in hits]}"

    def test_markupsafe_escape_not_matched(self):
        """markupsafe.escape must not trigger custom_sanitizer."""
        source = """
        from markupsafe import escape

        safe_text = escape(user_input)
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", CUSTOM_SANITIZER_MARKERS)
        assert len(hits) == 0, f"False positive hits: {[h.excerpt for h in hits]}"

    def test_actual_sanitize_call_matched(self):
        """A real sanitize() call should be detected."""
        source = """
        def process_input(data):
            cleaned = sanitize(data)
            return cleaned
        """
        idx = _build_index_from_source(source)
        hits = resolve_marker_hits(idx, "test_svc", CUSTOM_SANITIZER_MARKERS)
        assert len(hits) >= 1


# ─── ASTCodeIndex basic functionality ─────────────────────────────────────

class TestASTCodeIndexBasic:
    def test_find_imports(self):
        source = """
        from sqlalchemy.orm import Session
        from pydantic import BaseModel
        """
        idx = _build_index_from_source(source)
        hits = idx.find_imports("test_svc", "Session", from_module="sqlalchemy")
        assert len(hits) == 1
        assert hits[0].module_origin == "sqlalchemy.orm"

    def test_find_calls(self):
        source = """
        def setup():
            engine = create_engine("sqlite:///test.db")
        """
        idx = _build_index_from_source(source)
        hits = idx.find_calls("test_svc", "create_engine")
        assert len(hits) == 1

    def test_find_base_classes_with_exclude(self):
        source = """
        from pydantic import BaseModel
        class User(BaseModel):
            name: str
        class Item(Model):
            price: float
        """
        idx = _build_index_from_source(source)
        hits = idx.find_base_classes("test_svc", "Model", exclude_parents=["BaseModel"])
        assert len(hits) == 1
        assert hits[0].name == "Model"

    def test_find_decorators(self):
        source = """
        @require_auth
        def protected_route():
            pass
        """
        idx = _build_index_from_source(source)
        hits = idx.find_decorators("test_svc", "require_auth")
        assert len(hits) == 1

    def test_find_string_literals(self):
        source = """
        prefix = "/api/v1"
        """
        idx = _build_index_from_source(source)
        hits = idx.find_string_literals("test_svc", r"/api/v\d+")
        assert len(hits) == 1

    def test_find_keyword_args(self):
        source = """
        app = FastAPI(title="MyApp", version="1.0")
        """
        idx = _build_index_from_source(source)
        hits = idx.find_keyword_args("test_svc", "version", in_call="FastAPI")
        assert len(hits) == 1

    def test_text_with_boundary(self):
        source = """
        authorize(user, "admin")
        authorization = "Bearer token"
        """
        idx = _build_index_from_source(source)
        hits = idx.find_text_with_boundary("test_svc", "authorize")
        matched_lines = [h.excerpt for h in hits]
        assert any("authorize(user" in line for line in matched_lines)
        assert not any("authorization" in line for line in matched_lines)
