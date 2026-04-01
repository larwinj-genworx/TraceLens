from __future__ import annotations

from src.constants.defaults import SENSITIVE_FIELD_MARKERS
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

            if contract_fields:
                required_fields = {name for name, field in contract_fields.items() if field.required}
                provided_fields = set(payload_fields.keys())

                missing_fields = sorted(required_fields - provided_fields)
                if missing_fields:
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
                if extra_fields:
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

            elif payload_fields and endpoint.method.upper() in {"POST", "PUT", "PATCH"}:
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

        return issues

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
        normalized = field_name.lower()
        return any(marker in normalized for marker in SENSITIVE_FIELD_MARKERS)
