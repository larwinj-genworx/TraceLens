from __future__ import annotations

import re

from src.constants.defaults import is_sensitive_field_name
from src.schemas.internal import ServiceMatch, StaticAnalysisResult


class ContractValidator:
    def validate(self, matches: list[ServiceMatch]) -> list[dict]:
        issues: list[dict] = []

        for match in matches:
            call = match.call
            endpoint = match.endpoint
            endpoint_ref = f"{endpoint.method} {endpoint.path}"
            frontend_location = {"file": call.file, "line": call.line}
            backend_location = {"backend_file": endpoint.file, "backend_line": endpoint.line}

            if call.method.upper() != endpoint.method.upper():
                issues.append(
                    {
                        "type": "wrong_http_method",
                        "severity": "critical",
                        "service": match.frontend_repo,
                        "endpoint": endpoint_ref,
                        "description": (
                            f"Frontend uses {call.method.upper()} for {call.raw_url}, "
                            f"but backend contract expects {endpoint.method.upper()}."
                        ),
                        "file": call.file,
                        "line": call.line,
                        "evidence": {
                            "frontend_method": call.method.upper(),
                            "backend_method": endpoint.method.upper(),
                            "frontend_url": call.raw_url,
                            "backend_endpoint": endpoint.path,
                            **backend_location,
                        },
                        "impact": "Request fails or executes unintended code path under production traffic.",
                        "fix": "Align frontend HTTP verb with backend route method.",
                        "confidence": 0.95,
                    }
                )

            contract_fields = {field.name: field for field in endpoint.request_fields}
            payload_fields = call.payload_fields

            # GET, DELETE and HEAD carry no request body.  Comparing payload fields
            # against a schema captured from the function signature (e.g. a Depends()
            # dependency type) would produce entirely spurious "missing_fields" /
            # "extra_fields" issues on read-only endpoints.
            body_method = endpoint.method.upper() not in {"GET", "DELETE", "HEAD"}

            if contract_fields and body_method:
                required_fields = {name for name, field in contract_fields.items() if field.required}
                provided_fields = set(payload_fields.keys())

                # When the frontend passes a variable/expression as the payload
                # instead of an inline object literal, we cannot resolve its fields.
                # Reporting all required fields as "missing" would be a false positive.
                missing_fields = sorted(required_fields - provided_fields)
                if missing_fields and not call.payload_unresolved:
                    issues.append(
                        {
                            "type": "missing_fields",
                            "severity": "critical",
                            "service": match.frontend_repo,
                            "endpoint": endpoint_ref,
                            "description": (
                                f"Frontend payload misses required fields for {endpoint_ref}: {missing_fields}."
                            ),
                            "file": call.file,
                            "line": call.line,
                            "evidence": {
                                "missing_fields": missing_fields,
                                "required_fields": sorted(required_fields),
                                "payload_fields": sorted(provided_fields),
                                **backend_location,
                            },
                            "impact": "Validation errors and failed write operations in production.",
                            "fix": "Populate all required fields before request submission.",
                            "confidence": 0.93,
                        }
                    )

                extra_fields = sorted(provided_fields - set(contract_fields.keys()))
                if extra_fields and not call.payload_unresolved:
                    sensitive = [f for f in extra_fields if self._is_sensitive(f)]
                    severity = "critical" if sensitive else "high"
                    issue_type = "data_leakage" if sensitive else "extra_fields"
                    impact = (
                        "Sensitive data may be leaked to backend logs or downstream services."
                        if sensitive
                        else "Unexpected fields can bypass validation assumptions and create contract drift."
                    )
                    issues.append(
                        {
                            "type": issue_type,
                            "severity": severity,
                            "service": match.frontend_repo,
                            "endpoint": endpoint_ref,
                            "description": (
                                f"Frontend sends extra payload fields not in backend schema: {extra_fields}."
                            ),
                            "file": call.file,
                            "line": call.line,
                            "evidence": {
                                "extra_fields": extra_fields,
                                "sensitive_fields": sensitive,
                                "contract_fields": sorted(contract_fields.keys()),
                                **backend_location,
                            },
                            "impact": impact,
                            "fix": "Remove non-contract fields or extend backend schema intentionally.",
                            "confidence": 0.9,
                        }
                    )

                type_mismatches = self._detect_type_mismatches(payload_fields, contract_fields)
                if type_mismatches:
                    issues.append(
                        {
                            "type": "type_mismatch",
                            "severity": "high",
                            "service": match.frontend_repo,
                            "endpoint": endpoint_ref,
                            "file": call.file,
                            "line": call.line,
                            "description": "Payload field types differ from backend schema expectations.",
                            "evidence": {"mismatches": type_mismatches, **backend_location},
                            "impact": "Requests may fail validation or silently coerce values incorrectly.",
                            "fix": "Normalize frontend payload types to match backend schema definitions.",
                            "confidence": 0.86,
                        }
                    )

            elif payload_fields and body_method and endpoint.method.upper() in {"POST", "PUT", "PATCH"}:
                # Skip if the backend declares a request schema name (even without
                # resolved fields) or the payload was unresolved on the frontend side
                if endpoint.request_schema or call.payload_unresolved:
                    continue
                issues.append(
                    {
                        "type": "missing_backend_schema",
                        "severity": "high",
                        "service": endpoint.service,
                        "endpoint": endpoint_ref,
                        "file": endpoint.file,
                        "line": endpoint.line,
                        "description": "Write endpoint has no explicit request schema while frontend submits payload.",
                        "evidence": {
                            "payload_fields": sorted(payload_fields.keys()),
                            "backend_request_schema": endpoint.request_schema,
                            **frontend_location,
                        },
                        "impact": "Contract drift can go undetected and invalid payloads may reach business logic.",
                        "fix": "Define explicit Pydantic request model and enforce validation.",
                        "confidence": 0.8,
                    }
                )

            # ---- Response field validation ----
            response_consumed = call.response_consumed_fields
            response_schema = {f.name: f for f in endpoint.response_fields}

            if call.response_unresolved:
                pass  # cannot resolve consumed fields -- skip to avoid false positives
            elif response_consumed and response_schema:
                consumed_names = set(response_consumed.keys())
                schema_names = set(response_schema.keys())

                missing_resp = sorted(consumed_names - schema_names)
                if missing_resp:
                    issues.append(
                        {
                            "type": "response_field_missing",
                            "severity": "high",
                            "service": match.frontend_repo,
                            "endpoint": endpoint_ref,
                            "description": (
                                f"Frontend reads response fields not in backend schema: {missing_resp}."
                            ),
                            "file": call.file,
                            "line": call.line,
                            "evidence": {
                                "missing_response_fields": missing_resp,
                                "backend_response_fields": sorted(schema_names),
                                "frontend_consumed_fields": sorted(consumed_names),
                                **backend_location,
                            },
                            "impact": "Frontend will receive undefined values causing runtime errors.",
                            "fix": "Add missing fields to backend response model or remove frontend access.",
                            "confidence": 0.88,
                        }
                    )

                not_consumed = sorted(schema_names - consumed_names)
                if not_consumed:
                    issues.append(
                        {
                            "type": "response_field_not_consumed",
                            "severity": "medium",
                            "service": match.frontend_repo,
                            "endpoint": endpoint_ref,
                            "description": (
                                f"Backend returns fields the frontend never reads: {not_consumed}."
                            ),
                            "file": call.file,
                            "line": call.line,
                            "evidence": {
                                "not_consumed_fields": not_consumed,
                                "backend_response_fields": sorted(schema_names),
                                "frontend_consumed_fields": sorted(consumed_names),
                                **backend_location,
                            },
                            "impact": "Over-fetching wastes bandwidth and may expose unnecessary data.",
                            "fix": "Create a leaner response model or consume the fields in the frontend.",
                            "confidence": 0.82,
                        }
                    )

                resp_type_mismatches = self._detect_response_type_mismatches(
                    response_consumed, response_schema,
                )
                if resp_type_mismatches:
                    issues.append(
                        {
                            "type": "response_type_mismatch",
                            "severity": "high",
                            "service": match.frontend_repo,
                            "endpoint": endpoint_ref,
                            "file": call.file,
                            "line": call.line,
                            "description": "Frontend treats response fields as different types than backend declares.",
                            "evidence": {"mismatches": resp_type_mismatches, **backend_location},
                            "impact": "Silent type coercion can produce incorrect UI rendering or logic errors.",
                            "fix": "Align frontend type expectations with backend response schema.",
                            "confidence": 0.84,
                        }
                    )

            elif response_consumed and not response_schema:
                issues.append(
                    {
                        "type": "no_response_schema",
                        "severity": "medium",
                        "service": match.frontend_repo,
                        "endpoint": endpoint_ref,
                        "description": (
                            "Backend has no response_model but frontend reads specific response fields."
                        ),
                        "file": call.file,
                        "line": call.line,
                        "evidence": {
                            "frontend_consumed_fields": sorted(response_consumed.keys()),
                            "backend_response_schema": endpoint.response_schema,
                            **backend_location,
                        },
                        "impact": "Undocumented response contract risks silent breakage on backend changes.",
                        "fix": "Define an explicit response_model on the backend endpoint.",
                        "confidence": 0.78,
                    }
                )

        return issues

    def _detect_response_type_mismatches(
        self, consumed: dict[str, str], schema: dict[str, object],
    ) -> list[dict]:
        mismatches: list[dict] = []
        for field_name, fe_type in consumed.items():
            schema_field = schema.get(field_name)
            if schema_field is None:
                continue
            backend_type = self._normalize_backend_type(schema_field.field_type)
            frontend_type = self._normalize_frontend_type(fe_type)
            if backend_type == "unknown" or frontend_type == "unknown":
                continue
            if backend_type != frontend_type:
                mismatches.append({
                    "field": field_name,
                    "frontend_type": frontend_type,
                    "backend_type": backend_type,
                })
        return mismatches

    def _detect_type_mismatches(self, payload_fields: dict[str, str], contract_fields: dict[str, object]) -> list[dict]:
        mismatches: list[dict] = []
        for field_name, payload_type in payload_fields.items():
            contract_field = contract_fields.get(field_name)
            if contract_field is None:
                continue
            backend_type = self._normalize_backend_type(contract_field.field_type)
            frontend_type = self._normalize_frontend_type(payload_type)
            if backend_type == "unknown" or frontend_type == "unknown":
                continue
            if backend_type != frontend_type:
                mismatches.append(
                    {
                        "field": field_name,
                        "frontend_type": frontend_type,
                        "backend_type": backend_type,
                    }
                )
        return mismatches

    def _normalize_backend_type(self, raw: str) -> str:
        lowered = raw.lower()
        if any(token in lowered for token in ["str", "uuid", "email", "datetime", "date"]):
            return "string"
        if any(token in lowered for token in ["int", "float", "decimal", "conint", "confloat"]):
            return "number"
        if "bool" in lowered:
            return "boolean"
        if any(token in lowered for token in ["list", "set", "tuple", "sequence"]):
            return "array"
        if any(token in lowered for token in ["dict", "mapping", "object"]):
            return "object"
        if "none" in lowered:
            return "null"
        return "unknown"

    def _normalize_frontend_type(self, raw: str) -> str:
        lowered = raw.lower()
        if lowered in {"string", "number", "boolean", "array", "object", "null"}:
            return lowered
        return "unknown"

    def _is_sensitive(self, field_name: str) -> bool:
        return is_sensitive_field_name(field_name)

    # ── DTO enforcement validation ──────────────────────────────────────────

    _ORM_QUERY_PATTERNS: frozenset[str] = frozenset({
        "db.query", "session.query", "session.execute", "session.scalars",
        "session.get", "select", "insert", "update", "delete",
    })

    _ORM_QUERY_TERMINATORS: frozenset[str] = frozenset({
        "filter", "filter_by", "get", "get_or_none", "all", "first",
        "one", "one_or_none", "scalar", "scalars",
    })

    _DTO_SUFFIXES = re.compile(
        r"(Response|Out|Schema|DTO|Read|Public|View|Detail|List|Create|Update)$"
    )

    def validate_dto_enforcement(
        self, static_results: dict[str, StaticAnalysisResult],
    ) -> list[dict]:
        issues: list[dict] = []

        for static in static_results.values():
            orm_registry = static.orm_model_registry
            if not orm_registry:
                continue

            for endpoint in static.backend_endpoints:
                if endpoint.is_websocket:
                    continue

                # --- direct_orm_response ---
                if endpoint.orm_model_used:
                    orm_name = endpoint.orm_model_used
                    orm_cols = orm_registry.get(orm_name, [])
                    issues.append(
                        {
                            "type": "direct_orm_response",
                            "severity": "critical",
                            "service": endpoint.service,
                            "endpoint": f"{endpoint.method} {endpoint.path}",
                            "file": endpoint.file,
                            "line": endpoint.line,
                            "description": (
                                f"Endpoint uses ORM database model `{orm_name}` directly "
                                f"as response_model instead of a Pydantic DTO schema."
                            ),
                            "evidence": {
                                "orm_model": orm_name,
                                "response_schema": endpoint.response_schema,
                                "orm_columns": sorted(orm_cols),
                            },
                            "impact": (
                                "Internal database structure, sensitive columns, and "
                                "implementation details are exposed directly to API consumers."
                            ),
                            "fix": (
                                f"Create a dedicated Pydantic response schema (e.g. "
                                f"`{orm_name}Response`) with only the fields clients need."
                            ),
                            "confidence": 0.92,
                        }
                    )
                    continue

                # --- orm_field_exposure ---
                if (
                    endpoint.response_schema
                    and endpoint.response_fields
                    and not endpoint.orm_model_used
                ):
                    matching_orm = self._find_matching_orm_model(
                        endpoint.response_schema, orm_registry,
                    )
                    if matching_orm:
                        orm_name, orm_cols = matching_orm
                        if orm_cols:
                            dto_field_names = {f.name for f in endpoint.response_fields}
                            exposed = [c for c in orm_cols if c in dto_field_names]
                            if len(exposed) == len(orm_cols) and len(orm_cols) >= 3:
                                issues.append(
                                    {
                                        "type": "orm_field_exposure",
                                        "severity": "high",
                                        "service": endpoint.service,
                                        "endpoint": f"{endpoint.method} {endpoint.path}",
                                        "file": endpoint.file,
                                        "line": endpoint.line,
                                        "description": (
                                            f"Response DTO `{endpoint.response_schema}` exposes "
                                            f"all {len(orm_cols)} columns from ORM model "
                                            f"`{orm_name}` without filtering; acts as a "
                                            f"pass-through of database structure."
                                        ),
                                        "evidence": {
                                            "dto_schema": endpoint.response_schema,
                                            "orm_model": orm_name,
                                            "exposed_columns": sorted(exposed),
                                            "dto_field_count": len(dto_field_names),
                                            "orm_column_count": len(orm_cols),
                                        },
                                        "impact": (
                                            "The DTO mirrors the database schema exactly, "
                                            "defeating the purpose of a data transfer layer "
                                            "and risking exposure of internal columns."
                                        ),
                                        "fix": (
                                            f"Remove internal/sensitive columns from "
                                            f"`{endpoint.response_schema}` that clients don't need."
                                        ),
                                        "confidence": 0.80,
                                    }
                                )

                # --- missing_dto_layer ---
                if (
                    not endpoint.response_schema
                    and not endpoint.returns_file_response
                    and endpoint.status_code_literal != 204
                    and endpoint.method.upper() != "HEAD"
                    and self._has_orm_query_refs(endpoint.call_refs)
                ):
                    issues.append(
                        {
                            "type": "missing_dto_layer",
                            "severity": "high",
                            "service": endpoint.service,
                            "endpoint": f"{endpoint.method} {endpoint.path}",
                            "file": endpoint.file,
                            "line": endpoint.line,
                            "description": (
                                "Endpoint performs database queries but has no response_model, "
                                "returning raw ORM objects without serialization control."
                            ),
                            "evidence": {
                                "orm_query_refs": [
                                    r for r in endpoint.call_refs
                                    if self._is_orm_query_ref(r)
                                ][:10],
                                "response_schema": None,
                            },
                            "impact": (
                                "Without a response_model, FastAPI cannot filter or validate "
                                "outbound data, risking exposure of all model attributes "
                                "including sensitive or internal fields."
                            ),
                            "fix": (
                                "Define a Pydantic response schema with only the fields "
                                "clients need and set it as response_model on the decorator."
                            ),
                            "confidence": 0.78,
                        }
                    )

        return issues

    def _has_orm_query_refs(self, call_refs: list[str]) -> bool:
        for ref in call_refs:
            if self._is_orm_query_ref(ref):
                return True
        return False

    def _is_orm_query_ref(self, ref: str) -> bool:
        lowered = ref.lower()
        if any(p in lowered for p in self._ORM_QUERY_PATTERNS):
            return True
        short = ref.split(".")[-1]
        if short in self._ORM_QUERY_TERMINATORS:
            return True
        return False

    def _find_matching_orm_model(
        self, dto_name: str, orm_registry: dict[str, list[str]],
    ) -> tuple[str, list[str]] | None:
        base = self._DTO_SUFFIXES.sub("", dto_name)
        if not base:
            return None
        for orm_name, cols in orm_registry.items():
            if orm_name == base:
                return orm_name, cols
        return None
