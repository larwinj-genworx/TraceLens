"""Regression tests for DTO enforcement validation.

Covers the FastAPIParser ORM model registry and the ContractValidator
DTO enforcement issue detection (direct_orm_response, orm_field_exposure,
missing_dto_layer).
"""

from __future__ import annotations

import ast
import textwrap

import pytest

from src.analyzers.fastapi.parser import FastAPIParser
from src.contracts.validator import ContractValidator
from src.schemas.internal import (
    BackendEndpoint,
    SchemaField,
    StaticAnalysisResult,
)


# ─── Helpers ────────────────────────────────────────────────────────────────

def _make_endpoint(
    path: str = "/api/users",
    method: str = "GET",
    response_schema: str | None = None,
    response_fields: list[dict] | None = None,
    orm_model_used: str | None = None,
    call_refs: list[str] | None = None,
    returns_file_response: bool = False,
    status_code_literal: int | None = None,
) -> BackendEndpoint:
    r_fields = [SchemaField(**f) for f in (response_fields or [])]
    return BackendEndpoint(
        service="backend",
        file="app/routes.py",
        line=10,
        path=path,
        method=method,
        response_schema=response_schema,
        response_fields=r_fields,
        orm_model_used=orm_model_used,
        call_refs=call_refs or [],
        returns_file_response=returns_file_response,
        status_code_literal=status_code_literal,
    )


def _make_static(
    endpoints: list[BackendEndpoint],
    orm_registry: dict[str, list[str]] | None = None,
) -> dict[str, StaticAnalysisResult]:
    return {
        "backend": StaticAnalysisResult(
            repo="backend",
            backend_endpoints=endpoints,
            orm_model_registry=orm_registry or {},
        ),
    }


def _validate_dto(static: dict[str, StaticAnalysisResult]) -> list[dict]:
    return ContractValidator().validate_dto_enforcement(static)


# ─── FastAPIParser ORM registry tests ───────────────────────────────────────

class TestOrmModelRegistry:
    parser = FastAPIParser()

    def _build_orm_registry(self, source: str) -> dict[str, list[str]]:
        code = textwrap.dedent(source)
        tree = ast.parse(code)
        file_asts = {"test.py": (__import__("pathlib").Path("/tmp/test.py"), tree)}
        return self.parser._build_global_orm_models(file_asts)

    def test_sqlalchemy_base_with_tablename(self):
        reg = self._build_orm_registry("""\
            class User(Base):
                __tablename__ = "users"
                id = Column(Integer, primary_key=True)
                name = Column(String)
                password_hash = Column(String)
        """)
        assert "User" in reg
        assert "id" in reg["User"]
        assert "name" in reg["User"]
        assert "password_hash" in reg["User"]

    def test_sqlalchemy_declarative_base(self):
        reg = self._build_orm_registry("""\
            class User(DeclarativeBase):
                __tablename__ = "users"
                id = Column(Integer, primary_key=True)
        """)
        assert "User" in reg

    def test_sqlalchemy_mapped_column(self):
        reg = self._build_orm_registry("""\
            class User(Base):
                __tablename__ = "users"
                id: Mapped[int] = mapped_column(primary_key=True)
                name: Mapped[str] = mapped_column()
        """)
        assert "User" in reg
        assert "id" in reg["User"]
        assert "name" in reg["User"]

    def test_sqlalchemy_mapped_annotation_only(self):
        reg = self._build_orm_registry("""\
            class Item(Base):
                __tablename__ = "items"
                id: Mapped[int]
                title: Mapped[str]
        """)
        assert "Item" in reg
        assert "id" in reg["Item"]
        assert "title" in reg["Item"]

    def test_flask_sqlalchemy_db_model(self):
        reg = self._build_orm_registry("""\
            class Product(db.Model):
                id = Column(Integer, primary_key=True)
                name = Column(String)
        """)
        assert "Product" in reg

    def test_tortoise_model_with_column_defs(self):
        reg = self._build_orm_registry("""\
            class User(Model):
                id = fields.IntField(pk=True)
                name = fields.CharField(max_length=100)
        """)
        assert "User" in reg
        assert "id" in reg["User"]
        assert "name" in reg["User"]

    def test_pydantic_base_model_not_detected(self):
        """Pydantic BaseModel subclass must NOT be in the ORM registry."""
        reg = self._build_orm_registry("""\
            class UserResponse(BaseModel):
                id: int
                name: str
        """)
        assert "UserResponse" not in reg

    def test_plain_model_without_columns_not_detected(self):
        """A class named Model without ORM column patterns is not detected."""
        reg = self._build_orm_registry("""\
            class Config(Model):
                value = "something"
        """)
        assert "Config" not in reg

    def test_base_without_tablename_or_columns_not_detected(self):
        """Base subclass without __tablename__ or Column() is not detected."""
        reg = self._build_orm_registry("""\
            class AbstractMixin(Base):
                pass
        """)
        assert "AbstractMixin" not in reg

    def test_private_columns_excluded(self):
        reg = self._build_orm_registry("""\
            class User(Base):
                __tablename__ = "users"
                id = Column(Integer)
                _internal = Column(String)
        """)
        assert "User" in reg
        assert "_internal" not in reg["User"]


# ─── ContractValidator DTO enforcement tests ────────────────────────────────

class TestDirectOrmResponse:

    def test_orm_model_as_response_model(self):
        endpoint = _make_endpoint(
            response_schema="User",
            orm_model_used="User",
        )
        orm_reg = {"User": ["id", "name", "password_hash"]}
        issues = _validate_dto(_make_static([endpoint], orm_reg))
        types = {i["type"] for i in issues}
        assert "direct_orm_response" in types
        issue = next(i for i in issues if i["type"] == "direct_orm_response")
        assert issue["severity"] == "critical"
        assert "User" in issue["description"]

    def test_pydantic_dto_not_flagged(self):
        endpoint = _make_endpoint(
            response_schema="UserResponse",
            response_fields=[{"name": "id", "field_type": "int"}, {"name": "name", "field_type": "str"}],
        )
        orm_reg = {"User": ["id", "name", "password_hash"]}
        issues = _validate_dto(_make_static([endpoint], orm_reg))
        types = {i["type"] for i in issues}
        assert "direct_orm_response" not in types


class TestOrmFieldExposure:

    def test_dto_mirrors_all_orm_columns(self):
        endpoint = _make_endpoint(
            response_schema="UserResponse",
            response_fields=[
                {"name": "id", "field_type": "int"},
                {"name": "name", "field_type": "str"},
                {"name": "password_hash", "field_type": "str"},
                {"name": "internal_notes", "field_type": "str"},
            ],
        )
        orm_reg = {"User": ["id", "name", "password_hash", "internal_notes"]}
        issues = _validate_dto(_make_static([endpoint], orm_reg))
        types = {i["type"] for i in issues}
        assert "orm_field_exposure" in types
        issue = next(i for i in issues if i["type"] == "orm_field_exposure")
        assert issue["severity"] == "high"
        assert "UserResponse" in issue["description"]
        assert "User" in issue["description"]

    def test_dto_filters_sensitive_columns_no_issue(self):
        """DTO that removes some ORM columns is proper -- no issue."""
        endpoint = _make_endpoint(
            response_schema="UserResponse",
            response_fields=[
                {"name": "id", "field_type": "int"},
                {"name": "name", "field_type": "str"},
            ],
        )
        orm_reg = {"User": ["id", "name", "password_hash", "internal_notes"]}
        issues = _validate_dto(_make_static([endpoint], orm_reg))
        types = {i["type"] for i in issues}
        assert "orm_field_exposure" not in types

    def test_no_matching_orm_model_no_issue(self):
        """DTO with no matching ORM model name -- no issue."""
        endpoint = _make_endpoint(
            response_schema="WidgetOut",
            response_fields=[
                {"name": "id", "field_type": "int"},
                {"name": "name", "field_type": "str"},
            ],
        )
        orm_reg = {"User": ["id", "name", "password_hash"]}
        issues = _validate_dto(_make_static([endpoint], orm_reg))
        types = {i["type"] for i in issues}
        assert "orm_field_exposure" not in types

    def test_suffix_matching_works(self):
        """UserOut should match ORM model User."""
        endpoint = _make_endpoint(
            response_schema="UserOut",
            response_fields=[
                {"name": "id", "field_type": "int"},
                {"name": "name", "field_type": "str"},
                {"name": "email", "field_type": "str"},
            ],
        )
        orm_reg = {"User": ["id", "name", "email"]}
        issues = _validate_dto(_make_static([endpoint], orm_reg))
        types = {i["type"] for i in issues}
        assert "orm_field_exposure" in types

    def test_small_orm_model_not_flagged(self):
        """ORM model with < 3 columns should not trigger orm_field_exposure."""
        endpoint = _make_endpoint(
            response_schema="TagResponse",
            response_fields=[
                {"name": "id", "field_type": "int"},
                {"name": "name", "field_type": "str"},
            ],
        )
        orm_reg = {"Tag": ["id", "name"]}
        issues = _validate_dto(_make_static([endpoint], orm_reg))
        types = {i["type"] for i in issues}
        assert "orm_field_exposure" not in types


class TestMissingDtoLayer:

    def test_orm_query_without_response_model(self):
        endpoint = _make_endpoint(
            response_schema=None,
            call_refs=["db.query", "User", "first"],
        )
        orm_reg = {"User": ["id", "name"]}
        issues = _validate_dto(_make_static([endpoint], orm_reg))
        types = {i["type"] for i in issues}
        assert "missing_dto_layer" in types
        issue = next(i for i in issues if i["type"] == "missing_dto_layer")
        assert issue["severity"] == "high"

    def test_session_execute_without_response_model(self):
        endpoint = _make_endpoint(
            response_schema=None,
            call_refs=["session.execute", "select"],
        )
        orm_reg = {"User": ["id", "name"]}
        issues = _validate_dto(_make_static([endpoint], orm_reg))
        types = {i["type"] for i in issues}
        assert "missing_dto_layer" in types

    def test_with_response_model_no_issue(self):
        """Endpoint with response_model should not flag missing_dto_layer."""
        endpoint = _make_endpoint(
            response_schema="UserResponse",
            response_fields=[{"name": "id", "field_type": "int"}],
            call_refs=["db.query", "User", "first"],
        )
        orm_reg = {"User": ["id", "name"]}
        issues = _validate_dto(_make_static([endpoint], orm_reg))
        types = {i["type"] for i in issues}
        assert "missing_dto_layer" not in types

    def test_file_response_no_issue(self):
        """File response endpoints should not trigger missing_dto_layer."""
        endpoint = _make_endpoint(
            response_schema=None,
            call_refs=["db.query", "first"],
            returns_file_response=True,
        )
        orm_reg = {"User": ["id", "name"]}
        issues = _validate_dto(_make_static([endpoint], orm_reg))
        types = {i["type"] for i in issues}
        assert "missing_dto_layer" not in types

    def test_204_no_content_no_issue(self):
        """204 No Content endpoints should not trigger missing_dto_layer."""
        endpoint = _make_endpoint(
            response_schema=None,
            call_refs=["db.query", "delete"],
            status_code_literal=204,
        )
        orm_reg = {"User": ["id", "name"]}
        issues = _validate_dto(_make_static([endpoint], orm_reg))
        types = {i["type"] for i in issues}
        assert "missing_dto_layer" not in types

    def test_no_orm_queries_no_issue(self):
        """Endpoint without ORM queries should not flag missing_dto_layer."""
        endpoint = _make_endpoint(
            response_schema=None,
            call_refs=["some_service.get_data", "format_response"],
        )
        orm_reg = {"User": ["id", "name"]}
        issues = _validate_dto(_make_static([endpoint], orm_reg))
        types = {i["type"] for i in issues}
        assert "missing_dto_layer" not in types

    def test_no_orm_registry_no_issues(self):
        """When no ORM models are detected, no DTO issues should fire."""
        endpoint = _make_endpoint(
            response_schema=None,
            call_refs=["db.query", "first"],
        )
        issues = _validate_dto(_make_static([endpoint], {}))
        assert len(issues) == 0
