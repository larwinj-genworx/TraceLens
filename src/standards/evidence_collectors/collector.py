"""Main evidence collector that runs all category-specific collectors."""

from __future__ import annotations

import logging
from collections.abc import Callable

from src.schemas.internal import StaticAnalysisResult
from src.standards.evidence_collectors.auth_evidence import (
    collect_auth_evidence,
    collect_auth_mechanism_evidence,
    collect_authz_evidence,
    collect_ownership_evidence,
)
from src.standards.evidence_collectors.backend_evidence import (
    collect_error_handling_evidence,
    collect_folder_structure_evidence,
    collect_response_contract_evidence,
    collect_validation_evidence,
)
from src.standards.evidence_collectors.base import CategoryEvidenceResult
from src.standards.evidence_collectors.generic_evidence import (
    RepoCodeIndex,
    collect_generic_fastapi_category,
    collect_generic_react_category,
)
from src.standards.evidence_collectors.frontend_evidence import (
    collect_http_client_evidence,
    collect_token_storage_evidence,
)
from src.standards.resolver import ResolvedStandard

logger = logging.getLogger(__name__)


class StandardsEvidenceCollector:
    """Orchestrates all category evidence collectors and produces a combined result."""

    def __init__(self, resolved: ResolvedStandard) -> None:
        self.resolved = resolved
        self._fastapi_registry: dict[
            str, Callable[[dict[str, StaticAnalysisResult]], CategoryEvidenceResult]
        ] = {
            "auth_style": lambda static: collect_auth_evidence(self.resolved, static),
            "auth_mechanism": lambda static: collect_auth_mechanism_evidence(self.resolved, static),
            "authz_model": lambda static: collect_authz_evidence(self.resolved, static),
            "ownership_protection": lambda static: collect_ownership_evidence(self.resolved, static),
            "request_validation": lambda static: collect_validation_evidence(self.resolved, static),
            "response_contract": lambda static: collect_response_contract_evidence(self.resolved, static),
            "error_handling": lambda static: collect_error_handling_evidence(self.resolved, static),
        }
        self._react_registry: dict[
            str, Callable[[dict[str, StaticAnalysisResult]], CategoryEvidenceResult]
        ] = {
            "auth_token_storage": lambda static: collect_token_storage_evidence(self.resolved, static),
            "http_client": lambda static: collect_http_client_evidence(self.resolved, static),
        }

    def collect_all(
        self,
        static_results: dict[str, StaticAnalysisResult],
        repo_paths: dict[str, str] | None = None,
        repo_types: dict[str, str] | None = None,
    ) -> list[CategoryEvidenceResult]:
        """Run all applicable evidence collectors and return results."""

        results: list[CategoryEvidenceResult] = []

        if not self.resolved.has_standard():
            return results

        repo_index = RepoCodeIndex(repo_paths or {})
        fastapi_static = _filter_static_results_for_stack(
            static_results,
            stack="fastapi",
            repo_types=repo_types,
        )
        react_static = _filter_static_results_for_stack(
            static_results,
            stack="react",
            repo_types=repo_types,
        )

        # Backend (FastAPI) collectors by selected category.
        for category_id in self.resolved.fastapi.categories.keys():
            handler = self._fastapi_registry.get(category_id)
            if handler:
                category_result = handler(fastapi_static)
            else:
                category_result = collect_generic_fastapi_category(
                    self.resolved,
                    fastapi_static,
                    category_id,
                    repo_index,
                )
            if category_result.category != category_id:
                category_result.category = category_id
            results.append(category_result)

        # Frontend (React) collectors by selected category.
        for category_id in self.resolved.react.categories.keys():
            handler = self._react_registry.get(category_id)
            if handler:
                category_result = handler(react_static)
            else:
                category_result = collect_generic_react_category(
                    self.resolved,
                    react_static,
                    category_id,
                    repo_index,
                )
            if category_result.category != category_id:
                category_result.category = category_id
            results.append(category_result)

        # Folder structure (both stacks)
        if repo_paths:
            results.append(
                collect_folder_structure_evidence(
                    self.resolved,
                    repo_paths,
                    repo_types=repo_types,
                )
            )

        logger.info(
            "Standards evidence collection complete: %d categories evaluated",
            len(results),
        )
        return results


def _filter_static_results_for_stack(
    static_results: dict[str, StaticAnalysisResult],
    *,
    stack: str,
    repo_types: dict[str, str] | None,
) -> dict[str, StaticAnalysisResult]:
    filtered: dict[str, StaticAnalysisResult] = {}
    for repo_name, static in static_results.items():
        hint = (repo_types or {}).get(repo_name, "").lower()
        if stack == "fastapi":
            if hint in {"frontend"}:
                continue
            if hint in {"backend", "mixed"} or static.backend_endpoints:
                filtered[repo_name] = static
            continue
        if hint in {"backend"}:
            continue
        if hint in {"frontend", "mixed"} or static.frontend_calls:
            filtered[repo_name] = static
    return filtered
