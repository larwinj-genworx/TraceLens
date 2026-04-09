"""AST-based service call-chain tracer for FastAPI route handlers.

Traces 1-2 levels deep into service functions called from route handlers
and extracts behavioral signals (identity comparisons, authorization raises,
identity-based query filters) to detect ownership/tenant scoping that happens
at the service layer rather than inline in the route handler.

All detection is AST-structural — no keyword lists for naming conventions.
"""

from __future__ import annotations

import ast
import logging
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)

_IDENTITY_ATTRS: frozenset[str] = frozenset({
    "user_id", "owner_id", "tenant_id", "org_id", "organization_id",
    "account_id", "team_id", "workspace_id", "company_id", "group_id",
    "customer_id", "member_id", "creator_id", "author_id",
})

_HTTP_ERROR_STATUS_CODES: frozenset[int] = frozenset({401, 403, 404})


@dataclass
class ServiceCallSignals:
    """Behavioral signals extracted from service-layer function calls."""

    has_identity_comparison: bool = False
    has_authorization_raise: bool = False
    has_identity_filter: bool = False
    identity_attrs_compared: list[str] = field(default_factory=list)
    traced_depth: int = 0


class ServiceCallTracer:
    """Traces service function calls from route handlers via AST analysis."""

    def __init__(
        self,
        file_asts: dict[str, tuple[Path, ast.Module]],
        module_to_file: dict[str, str] | None = None,
    ) -> None:
        self._file_asts = file_asts
        self._module_to_file = module_to_file or {}
        self._func_index: dict[str, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        self._cache: dict[str, ServiceCallSignals] = {}
        self._build_func_index()

    def _build_func_index(self) -> None:
        for file_str, (_, tree) in self._file_asts.items():
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._func_index[node.name] = (file_str, node)

    def trace_handler_calls(
        self,
        handler_node: ast.FunctionDef | ast.AsyncFunctionDef,
        max_depth: int = 2,
    ) -> ServiceCallSignals:
        """Trace all direct call targets from a route handler and merge signals."""
        combined = ServiceCallSignals()
        callee_names = self._extract_callee_names(handler_node)

        for name in callee_names:
            signals = self._trace_function(name, depth=0, max_depth=max_depth)
            self._merge_signals(combined, signals)

        combined.traced_depth = max_depth
        return combined

    def _trace_function(
        self, func_name: str, depth: int, max_depth: int,
    ) -> ServiceCallSignals:
        if depth > max_depth:
            return ServiceCallSignals()

        cache_key = f"{func_name}:{depth}"
        if cache_key in self._cache:
            return self._cache[cache_key]

        entry = self._func_index.get(func_name)
        if not entry:
            return ServiceCallSignals()

        _file_str, node = entry
        signals = ServiceCallSignals()

        identity_attrs = self._detect_identity_comparisons(node)
        if identity_attrs:
            signals.has_identity_comparison = True
            signals.identity_attrs_compared = identity_attrs

        signals.has_authorization_raise = self._detect_authorization_raises(node)
        signals.has_identity_filter = self._detect_identity_query_filters(node)

        if depth < max_depth:
            sub_callees = self._extract_callee_names(node)
            for sub_name in sub_callees:
                if sub_name == func_name:
                    continue
                sub_signals = self._trace_function(sub_name, depth + 1, max_depth)
                self._merge_signals(signals, sub_signals)

        self._cache[cache_key] = signals
        return signals

    def _extract_callee_names(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[str]:
        """Extract unique callee function names from a function body."""
        names: set[str] = set()
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            name = self._resolve_callable_name(child.func)
            if name:
                short = name.split(".")[-1]
                names.add(short)
        return list(names)

    def _detect_identity_comparisons(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> list[str]:
        """Detect ast.Compare nodes where an identity attribute is compared.

        Catches patterns like:
            subject.organization_id != user.organization_id
            session.user_id != user_id
            if resource.owner_id == current_user["id"]:
        """
        found_attrs: set[str] = set()
        for child in ast.walk(node):
            if not isinstance(child, ast.Compare):
                continue
            all_elements = [child.left, *child.comparators]
            for elem in all_elements:
                attr_name = self._extract_identity_attr(elem)
                if attr_name:
                    found_attrs.add(attr_name)
        return sorted(found_attrs)

    def _extract_identity_attr(self, node: ast.expr) -> str | None:
        """Check if an AST expression references an identity-bearing attribute."""
        if isinstance(node, ast.Attribute):
            if node.attr in _IDENTITY_ATTRS:
                return node.attr
        if isinstance(node, ast.Subscript):
            if isinstance(node.slice, ast.Constant) and isinstance(node.slice.value, str):
                if node.slice.value in _IDENTITY_ATTRS:
                    return node.slice.value
        if isinstance(node, ast.Name):
            if node.id in _IDENTITY_ATTRS:
                return node.id
        return None

    def _detect_authorization_raises(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        """Detect raise statements with HTTP 401/403/404 status codes."""
        for child in ast.walk(node):
            if not isinstance(child, ast.Raise) or child.exc is None:
                continue
            exc = child.exc
            if not isinstance(exc, ast.Call):
                continue
            status = self._extract_status_code(exc)
            if status in _HTTP_ERROR_STATUS_CODES:
                return True
        return False

    def _extract_status_code(self, call_node: ast.Call) -> int | None:
        """Extract numeric status code from an exception constructor."""
        for kw in call_node.keywords:
            if kw.arg == "status_code":
                return self._resolve_status_value(kw.value)
        if call_node.args:
            return self._resolve_status_value(call_node.args[0])
        return None

    def _resolve_status_value(self, node: ast.expr) -> int | None:
        """Resolve an AST node to a numeric HTTP status code."""
        if isinstance(node, ast.Constant) and isinstance(node.value, int):
            return node.value
        if isinstance(node, ast.Attribute):
            attr = node.attr.upper()
            if "401" in attr or "UNAUTHORIZED" in attr:
                return 401
            if "403" in attr or "FORBIDDEN" in attr:
                return 403
            if "404" in attr or "NOT_FOUND" in attr:
                return 404
        return None

    def _detect_identity_query_filters(
        self, node: ast.FunctionDef | ast.AsyncFunctionDef,
    ) -> bool:
        """Detect function calls with identity-bearing keyword arguments.

        Catches patterns like:
            repo.get_subject_for_owner(subject_id, owner_id=current_user["id"])
            service.list_items(user_id=user_id)
        """
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            for kw in child.keywords:
                if kw.arg and kw.arg in _IDENTITY_ATTRS:
                    return True
        return False

    @staticmethod
    def _merge_signals(target: ServiceCallSignals, source: ServiceCallSignals) -> None:
        if source.has_identity_comparison:
            target.has_identity_comparison = True
            for attr in source.identity_attrs_compared:
                if attr not in target.identity_attrs_compared:
                    target.identity_attrs_compared.append(attr)
        if source.has_authorization_raise:
            target.has_authorization_raise = True
        if source.has_identity_filter:
            target.has_identity_filter = True

    @staticmethod
    def _resolve_callable_name(node: ast.AST | None) -> str:
        if node is None:
            return ""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            left = ServiceCallTracer._resolve_callable_name(node.value)
            return f"{left}.{node.attr}" if left else node.attr
        if isinstance(node, ast.Call):
            return ServiceCallTracer._resolve_callable_name(node.func)
        return ""
