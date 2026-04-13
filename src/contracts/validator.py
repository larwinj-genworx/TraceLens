from __future__ import annotations

from src.constants.defaults import is_sensitive_field_name
from src.schemas.internal import ServiceMatch


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
