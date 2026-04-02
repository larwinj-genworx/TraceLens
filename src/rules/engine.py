from __future__ import annotations

from src.rules.rules import (
    rule_broken_service_connection,
    rule_contract_violations,
    rule_data_leakage,
    rule_hardcoded_configs,
    rule_mandatory_flow_violations,
    rule_missing_auth,
    rule_missing_validation,
    rule_over_fetching,
    rule_partial_mismatch,
    rule_redundant_calls,
)
from src.schemas.internal import AnalysisContext
from src.schemas.issues import Issue, Severity


class RuleEngine:
    def evaluate(self, context: AnalysisContext) -> list[Issue]:
        generated: list[Issue] = []

        generated.extend(rule_contract_violations(context))
        generated.extend(rule_data_leakage(context))
        generated.extend(rule_broken_service_connection(context))
        generated.extend(rule_missing_auth(context))
        generated.extend(rule_partial_mismatch(context))
        generated.extend(rule_missing_validation(context))
        generated.extend(rule_mandatory_flow_violations(context))
        generated.extend(rule_hardcoded_configs(context))
        generated.extend(rule_over_fetching(context))
        generated.extend(rule_redundant_calls(context))

        deduped: list[Issue] = []
        seen: set[tuple[str, str, str | None, str]] = set()
        for issue in generated:
            key = (issue.type, issue.service, issue.endpoint, issue.description)
            if key in seen:
                continue
            seen.add(key)
            deduped.append(issue)

        severity_order = {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
        }
        deduped.sort(key=lambda item: (severity_order[item.severity], -item.confidence, item.type, item.service))
        return deduped
