"""Convert standards evidence violations into first-class Issue objects."""

from __future__ import annotations

from src.schemas.issues import Issue, Severity
from src.standards.evidence_collectors.base import CategoryEvidenceResult

_CATEGORY_SEVERITY: dict[str, Severity] = {
    "auth_style": Severity.CRITICAL,
    "auth_mechanism": Severity.CRITICAL,
    "authz_model": Severity.CRITICAL,
    "authz_enforcement": Severity.CRITICAL,
    "ownership_protection": Severity.CRITICAL,
    "request_validation": Severity.HIGH,
    "response_contract": Severity.HIGH,
    "error_handling": Severity.HIGH,
    "rate_limiting": Severity.HIGH,
    "input_sanitization": Severity.HIGH,
    "secret_management": Severity.CRITICAL,
    "idempotency": Severity.HIGH,
    "cors_config": Severity.HIGH,
    "cors_policy": Severity.HIGH,
    "auth_token_storage": Severity.CRITICAL,
    "http_client": Severity.MEDIUM,
    "api_layer_pattern": Severity.MEDIUM,
    "folder_structure": Severity.MEDIUM,
}

_CATEGORY_FIX_HINTS: dict[str, str] = {
    "auth_style": "Apply the declared authentication style to all protected endpoints.",
    "auth_mechanism": "Unify authentication mechanism with the selected standard.",
    "authz_model": "Add authorization checks matching the selected model.",
    "authz_enforcement": "Move authorization checks to the declared enforcement layer.",
    "ownership_protection": "Add ownership/tenant checks before resource access.",
    "request_validation": "Validate write payloads using the selected validation strategy.",
    "response_contract": "Enforce response schema consistently for data endpoints.",
    "error_handling": "Apply the declared error-handling strategy consistently.",
    "rate_limiting": "Implement the selected rate-limiting strategy where applicable.",
    "input_sanitization": "Sanitize or validate input before risky operations.",
    "secret_management": "Move sensitive credentials to the declared secret-management approach.",
    "idempotency": "Add idempotency protection for write operations.",
    "auth_token_storage": "Store auth tokens exactly as declared in the standard.",
    "folder_structure": "Align repository folders with the declared template.",
}


def convert_evidence_to_issues(
    evidence_results: list[CategoryEvidenceResult],
) -> list[Issue]:
    issues: list[Issue] = []

    for category_result in evidence_results:
        category = category_result.category
        declared_style = category_result.declared_style
        severity = _CATEGORY_SEVERITY.get(category, Severity.MEDIUM)
        fix_hint = _CATEGORY_FIX_HINTS.get(
            category,
            "Align implementation with the selected TraceLens standard style.",
        )

        violation_items = [
            item for item in category_result.evidence_items if item.status == "violation"
        ]

        for item in violation_items:
            issue_type = f"standards_violation_{category}"
            if declared_style:
                issue_type = f"{issue_type}_{declared_style}"

            message = item.message or (
                f"Implementation violates selected standard in category '{category}'."
            )
            issue = Issue(
                type=issue_type,
                severity=severity,
                service=item.service or "unknown_service",
                endpoint=item.endpoint,
                file=item.file or None,
                line=item.line,
                description=message,
                evidence={
                    "category": category,
                    "declared_style": declared_style,
                    "detector": "standards_evidence",
                    "details": item.details,
                    "confidence": item.confidence,
                },
                impact=f"Selected TraceLens standard is not enforced for category '{category}'.",
                fix=fix_hint,
                confidence=min(max(item.confidence, 0.65), 0.98),
                source="standards_engine",
                provenance=["standards_engine"],
            )
            issues.append(issue)

        if (
            category_result.overall_status == "non_compliant"
            and not violation_items
            and category_result.evidence_items
        ):
            issue = Issue(
                type=f"standards_violation_{category}",
                severity=severity,
                service=category_result.evidence_items[0].service or "unknown_service",
                endpoint=None,
                file=None,
                line=None,
                description=(
                    f"Category '{category}' is non-compliant with declared style '{declared_style}'."
                ),
                evidence={
                    "category": category,
                    "declared_style": declared_style,
                    "detector": "standards_evidence",
                },
                impact=f"TraceLens standard is not fully enforced for '{category}'.",
                fix=fix_hint,
                confidence=0.75,
                source="standards_engine",
                provenance=["standards_engine"],
            )
            issues.append(issue)

    return issues

