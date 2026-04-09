"""Track standards coverage and detect unchecked units."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

from src.schemas.internal import FrontendCall, StaticAnalysisResult
from src.standards.evidence_collectors.base import CategoryEvidenceResult
from src.standards.resolver import ResolvedStandard

logger = logging.getLogger(__name__)

_FASTAPI_ENDPOINT_SCOPED = {
    "auth_style",
    "auth_mechanism",
    "authz_model",
    "authz_enforcement",
    "ownership_protection",
    "request_validation",
    "response_contract",
    "error_handling",
    "rate_limiting",
    "input_sanitization",
    "idempotency",
}

_REACT_CALL_SCOPED = {
    "http_client",
    "auth_token_storage",
    "api_layer_pattern",
}

_WRITE_METHODS = {"POST", "PUT", "PATCH", "DELETE"}


@dataclass
class CoverageCell:
    stack: str
    endpoint: str
    service: str
    category: str
    file: str | None = None
    line: int | None = None
    checked: bool = False
    status: str = "unchecked"


@dataclass
class CoverageMatrix:
    cells: list[CoverageCell] = field(default_factory=list)
    unchecked_count: int = 0
    total_count: int = 0
    coverage_pct: float = 0.0

    def to_dict(self) -> dict[str, Any]:
        rows = [
            {
                "stack": c.stack,
                "endpoint": c.endpoint,
                "service": c.service,
                "category": c.category,
                "checked": c.checked,
                "status": c.status,
                "file": c.file,
                "line": c.line,
            }
            for c in self.cells
        ]
        return {
            "total_checks": self.total_count,
            "checked": self.total_count - self.unchecked_count,
            "unchecked": self.unchecked_count,
            "coverage_pct": round(self.coverage_pct, 1),
            "rows": rows,
            "unchecked_details": [row for row in rows if not row["checked"]],
        }


class EndpointCoverageTracker:
    """Maintains a category x unit matrix to ensure strict standards coverage."""

    def __init__(self, resolved: ResolvedStandard) -> None:
        self.resolved = resolved
        self._cells: dict[str, CoverageCell] = {}

    def _cell_key(self, service: str, endpoint: str, category: str) -> str:
        return f"{service}|{endpoint}|{category}"

    def build_matrix(
        self,
        static_results: dict[str, StaticAnalysisResult],
        repo_types: dict[str, str] | None = None,
    ) -> None:
        for repo_name, static in static_results.items():
            repo_type = (repo_types or {}).get(repo_name, "").lower()
            supports_fastapi = _supports_stack("fastapi", static, repo_type)
            supports_react = _supports_stack("react", static, repo_type)

            if supports_fastapi:
                for category in self.resolved.fastapi.categories.keys():
                    if category in _FASTAPI_ENDPOINT_SCOPED:
                        for ep in static.backend_endpoints:
                            if not _is_endpoint_applicable(category, ep.method, ep.path):
                                continue
                            endpoint_key = f"{ep.method} {ep.path}"
                            self._cells[self._cell_key(repo_name, endpoint_key, category)] = CoverageCell(
                                stack="fastapi",
                                endpoint=endpoint_key,
                                service=repo_name,
                                category=category,
                                file=ep.file,
                                line=ep.line,
                            )
                    else:
                        endpoint_key = f"repo::{repo_name}"
                        self._cells[self._cell_key(repo_name, endpoint_key, category)] = CoverageCell(
                            stack="fastapi",
                            endpoint=endpoint_key,
                            service=repo_name,
                            category=category,
                        )

            if supports_react:
                for category in self.resolved.react.categories.keys():
                    if category in _REACT_CALL_SCOPED and static.frontend_calls:
                        for call in static.frontend_calls:
                            endpoint_key = _frontend_call_key(call)
                            self._cells[self._cell_key(repo_name, endpoint_key, category)] = CoverageCell(
                                stack="react",
                                endpoint=endpoint_key,
                                service=repo_name,
                                category=category,
                                file=call.file,
                                line=call.line,
                            )
                    else:
                        endpoint_key = f"repo::{repo_name}"
                        self._cells[self._cell_key(repo_name, endpoint_key, category)] = CoverageCell(
                            stack="react",
                            endpoint=endpoint_key,
                            service=repo_name,
                            category=category,
                        )

    def mark_checked(
        self,
        evidence_results: list[CategoryEvidenceResult],
    ) -> None:
        for cat_result in evidence_results:
            category = cat_result.category
            if not cat_result.evidence_items:
                continue

            for ev in cat_result.evidence_items:
                if not ev.service:
                    continue
                if ev.endpoint:
                    key = self._cell_key(ev.service, ev.endpoint, category)
                    cell = self._cells.get(key)
                    if cell:
                        cell.checked = True
                        cell.status = ev.status
                        if ev.file:
                            cell.file = ev.file
                        if ev.line is not None:
                            cell.line = ev.line
                        continue

                for cell in self._cells.values():
                    if cell.service != ev.service or cell.category != category:
                        continue
                    cell.checked = True
                    if ev.status:
                        cell.status = ev.status
                    if ev.file and not cell.file:
                        cell.file = ev.file
                    if ev.line is not None and cell.line is None:
                        cell.line = ev.line

    def get_matrix(self) -> CoverageMatrix:
        cells = list(self._cells.values())
        unchecked = [c for c in cells if not c.checked]
        total = len(cells)
        matrix = CoverageMatrix(
            cells=cells,
            unchecked_count=len(unchecked),
            total_count=total,
            coverage_pct=(((total - len(unchecked)) / total) * 100) if total > 0 else 100.0,
        )
        if unchecked:
            logger.warning(
                "Coverage gap: %d/%d endpoint-category pairs unchecked",
                len(unchecked),
                total,
            )
        return matrix


def _is_endpoint_applicable(category: str, method: str, path: str) -> bool:
    method_upper = method.upper()
    if category in {"request_validation", "authz_model", "authz_enforcement", "idempotency"}:
        return method_upper in _WRITE_METHODS
    if category == "ownership_protection":
        return "{" in path
    return True


def _frontend_call_key(call: FrontendCall) -> str:
    return f"{call.method.upper()} {call.raw_url}"


def _supports_stack(stack: str, static: StaticAnalysisResult, repo_type: str) -> bool:
    if stack == "fastapi":
        if repo_type == "frontend":
            return False
        if repo_type in {"backend", "mixed"}:
            return True
        return bool(static.backend_endpoints)
    if repo_type == "backend":
        return False
    if repo_type in {"frontend", "mixed"}:
        return True
    return bool(static.frontend_calls)
