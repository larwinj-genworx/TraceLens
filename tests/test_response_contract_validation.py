"""Regression tests for response field contract validation.

Covers the ReactParser response-consumption extraction and the
ContractValidator response-side issue detection.
"""

from __future__ import annotations

import pytest

from src.analyzers.react.parser import ReactParser
from src.contracts.validator import ContractValidator
from src.schemas.internal import (
    BackendEndpoint,
    FrontendCall,
    SchemaField,
    ServiceMatch,
)


# ─── Helpers ────────────────────────────────────────────────────────────────

def _make_endpoint(
    path: str = "/api/users",
    method: str = "GET",
    response_fields: list[dict] | None = None,
    response_schema: str | None = "UserResponse",
    request_fields: list[dict] | None = None,
) -> BackendEndpoint:
    r_fields = [SchemaField(**f) for f in (response_fields or [])]
    req_fields = [SchemaField(**f) for f in (request_fields or [])]
    return BackendEndpoint(
        service="backend",
        file="app/routes.py",
        line=10,
        path=path,
        method=method,
        response_schema=response_schema,
        response_fields=r_fields,
        request_fields=req_fields,
    )


def _make_call(
    raw_url: str = "/api/users",
    method: str = "GET",
    response_consumed_fields: dict[str, str] | None = None,
    response_unresolved: bool = False,
    payload_fields: dict[str, str] | None = None,
) -> FrontendCall:
    return FrontendCall(
        service="frontend",
        file="src/api.ts",
        line=5,
        raw_url=raw_url,
        method=method,
        response_consumed_fields=response_consumed_fields or {},
        response_unresolved=response_unresolved,
        payload_fields=payload_fields or {},
    )


def _make_match(
    call: FrontendCall, endpoint: BackendEndpoint,
) -> ServiceMatch:
    return ServiceMatch(
        frontend_repo="frontend",
        backend_repo="backend",
        call=call,
        endpoint=endpoint,
    )


def _validate(matches: list[ServiceMatch]) -> list[dict]:
    return ContractValidator().validate(matches)


# ─── ReactParser response extraction tests ──────────────────────────────────

class TestReactParserResponseExtraction:
    parser = ReactParser()

    def test_destructured_fetch_json(self):
        code = """\
const { name, email } = await fetch('/api/users').then(r => r.json());
console.log(name, email);
"""
        calls = self.parser._extract_fetch_calls("svc", "file.ts", code)
        assert len(calls) == 1
        assert "name" in calls[0].response_consumed_fields
        assert "email" in calls[0].response_consumed_fields
        assert not calls[0].response_unresolved

    def test_axios_data_destructure(self):
        code = """\
const { data: { user, token } } = await axios.get('/api/auth');
"""
        calls = self.parser._extract_axios_method_calls("svc", "file.ts", code)
        assert len(calls) == 1
        assert "user" in calls[0].response_consumed_fields
        assert "token" in calls[0].response_consumed_fields

    def test_variable_dot_access_axios(self):
        code = """\
const res = await axios.get('/api/users');
console.log(res.data.userName);
return res.data.email;
"""
        calls = self.parser._extract_axios_method_calls("svc", "file.ts", code)
        assert len(calls) == 1
        assert "userName" in calls[0].response_consumed_fields
        assert "email" in calls[0].response_consumed_fields

    def test_variable_json_then_dot(self):
        code = """\
const response = await fetch('/api/profile');
const data = await response.json();
setName(data.fullName);
setAge(data.age);
"""
        calls = self.parser._extract_fetch_calls("svc", "file.ts", code)
        assert len(calls) == 1
        assert "fullName" in calls[0].response_consumed_fields
        assert "age" in calls[0].response_consumed_fields

    def test_unresolved_variable_no_access(self):
        code = """\
const result = await fetch('/api/data').then(r => r.json());
processData(result);
"""
        calls = self.parser._extract_fetch_calls("svc", "file.ts", code)
        assert len(calls) == 1
        assert calls[0].response_unresolved is True
        assert calls[0].response_consumed_fields == {}

    def test_then_chain_destructuring(self):
        code = """\
fetch('/api/items')
  .then(res => res.json())
  .then(({ items, total }) => {
    setItems(items);
    setTotal(total);
  });
"""
        calls = self.parser._extract_fetch_calls("svc", "file.ts", code)
        assert len(calls) == 1
        assert "items" in calls[0].response_consumed_fields
        assert "total" in calls[0].response_consumed_fields

    def test_secondary_destructuring(self):
        code = """\
const res = await axios.get('/api/users');
const { name, id } = res.data;
"""
        calls = self.parser._extract_axios_method_calls("svc", "file.ts", code)
        assert len(calls) == 1
        assert "name" in calls[0].response_consumed_fields
        assert "id" in calls[0].response_consumed_fields

    def test_no_response_access_no_false_positive(self):
        code = """\
await fetch('/api/logout', { method: 'POST' });
navigate('/login');
"""
        calls = self.parser._extract_fetch_calls("svc", "file.ts", code)
        assert len(calls) == 1
        assert calls[0].response_consumed_fields == {}
        assert calls[0].response_unresolved is False

    def test_bracket_access(self):
        code = """\
const res = await axios.get('/api/config');
const theme = res.data["theme"];
const lang = res.data["language"];
"""
        calls = self.parser._extract_axios_method_calls("svc", "file.ts", code)
        assert len(calls) == 1
        assert "theme" in calls[0].response_consumed_fields
        assert "language" in calls[0].response_consumed_fields

    def test_custom_client_response(self):
        code = """\
const res = await apiClient.get('/api/users');
setUsers(res.data.users);
"""
        calls = self.parser._extract_custom_http_calls("svc", "file.ts", code)
        assert len(calls) == 1
        assert "users" in calls[0].response_consumed_fields


# ─── ContractValidator response field tests ─────────────────────────────────

class TestContractValidatorResponseFields:

    def test_response_field_missing(self):
        """FE reads 'email' but backend only returns 'name'."""
        endpoint = _make_endpoint(
            response_fields=[
                {"name": "name", "field_type": "str"},
            ],
        )
        call = _make_call(response_consumed_fields={"name": "unknown", "email": "unknown"})
        issues = _validate([_make_match(call, endpoint)])
        types = {i["type"] for i in issues}
        assert "response_field_missing" in types
        issue = next(i for i in issues if i["type"] == "response_field_missing")
        assert "email" in issue["evidence"]["missing_response_fields"]

    def test_response_field_not_consumed(self):
        """Backend returns 3 fields but FE only reads 'name'."""
        endpoint = _make_endpoint(
            response_fields=[
                {"name": "name", "field_type": "str"},
                {"name": "email", "field_type": "str"},
                {"name": "id", "field_type": "int"},
            ],
        )
        call = _make_call(response_consumed_fields={"name": "unknown"})
        issues = _validate([_make_match(call, endpoint)])
        types = {i["type"] for i in issues}
        assert "response_field_not_consumed" in types
        issue = next(i for i in issues if i["type"] == "response_field_not_consumed")
        assert "email" in issue["evidence"]["not_consumed_fields"]
        assert "id" in issue["evidence"]["not_consumed_fields"]

    def test_exact_match_no_issues(self):
        """FE consumes exactly the same fields backend returns -- no response issues."""
        endpoint = _make_endpoint(
            response_fields=[
                {"name": "name", "field_type": "str"},
                {"name": "email", "field_type": "str"},
            ],
        )
        call = _make_call(response_consumed_fields={"name": "unknown", "email": "unknown"})
        issues = _validate([_make_match(call, endpoint)])
        resp_types = {
            i["type"] for i in issues
            if i["type"] in {
                "response_field_missing", "response_field_not_consumed",
                "response_type_mismatch", "no_response_schema",
            }
        }
        assert len(resp_types) == 0

    def test_unresolved_skips_validation(self):
        """When response_unresolved=True, no false positive response issues."""
        endpoint = _make_endpoint(
            response_fields=[
                {"name": "name", "field_type": "str"},
                {"name": "email", "field_type": "str"},
            ],
        )
        call = _make_call(response_unresolved=True)
        issues = _validate([_make_match(call, endpoint)])
        resp_types = {
            i["type"] for i in issues
            if i["type"].startswith("response_") or i["type"] == "no_response_schema"
        }
        assert len(resp_types) == 0

    def test_response_type_mismatch(self):
        """FE treats 'id' as string but backend declares int."""
        endpoint = _make_endpoint(
            response_fields=[
                {"name": "id", "field_type": "int"},
                {"name": "name", "field_type": "str"},
            ],
        )
        call = _make_call(response_consumed_fields={"id": "string", "name": "string"})
        issues = _validate([_make_match(call, endpoint)])
        types = {i["type"] for i in issues}
        assert "response_type_mismatch" in types
        issue = next(i for i in issues if i["type"] == "response_type_mismatch")
        assert any(m["field"] == "id" for m in issue["evidence"]["mismatches"])

    def test_no_response_schema(self):
        """Backend has no response_model but FE reads fields."""
        endpoint = _make_endpoint(response_fields=[], response_schema=None)
        call = _make_call(response_consumed_fields={"name": "unknown"})
        issues = _validate([_make_match(call, endpoint)])
        types = {i["type"] for i in issues}
        assert "no_response_schema" in types

    def test_get_endpoint_response_validated(self):
        """GET endpoint with response schema should still be validated."""
        endpoint = _make_endpoint(
            method="GET",
            response_fields=[
                {"name": "name", "field_type": "str"},
            ],
        )
        call = _make_call(
            method="GET",
            response_consumed_fields={"name": "unknown", "avatar": "unknown"},
        )
        issues = _validate([_make_match(call, endpoint)])
        types = {i["type"] for i in issues}
        assert "response_field_missing" in types

    def test_no_response_consumed_no_issues(self):
        """When FE doesn't consume any response fields, no response issues."""
        endpoint = _make_endpoint(
            response_fields=[
                {"name": "name", "field_type": "str"},
            ],
        )
        call = _make_call(response_consumed_fields={})
        issues = _validate([_make_match(call, endpoint)])
        resp_types = {
            i["type"] for i in issues
            if i["type"].startswith("response_") or i["type"] == "no_response_schema"
        }
        assert len(resp_types) == 0
