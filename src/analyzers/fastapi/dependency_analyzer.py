"""AST-based dependency classification for FastAPI endpoints.

Classifies dependency functions by their *behavior* (what they do) rather
than their *name* (what they're called), making detection resilient to
arbitrary naming conventions.
"""

from __future__ import annotations

import ast
import logging
import re
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class DependencyClassification:
    """Classification result for a single dependency function."""

    func_name: str
    file: str
    classification: str  # "auth", "authz", "ownership", "db", "other"
    sub_type: str | None = None  # "jwt_bearer", "rbac", "tenant_scope", etc.
    raises_401: bool = False
    raises_403: bool = False
    reads_token: bool = False
    checks_role: bool = False
    filters_by_user: bool = False
    inner_deps: list[str] = field(default_factory=list)


@dataclass
class AuthMiddlewareAnalysis:
    """Analysis result for an auth middleware class."""

    middleware_name: str
    mechanism: str  # "jwt_bearer", "session", "api_key", "unknown"
    public_paths: list[str] = field(default_factory=list)
    websocket_excluded: bool = False
    sets_request_state: bool = False


class DependencyAnalyzer:
    """Performs deep AST analysis to classify dependency functions semantically."""

    def __init__(
        self,
        file_asts: dict[str, tuple[Path, ast.Module]],
        module_to_file: dict[str, str] | None = None,
    ) -> None:
        self._file_asts = file_asts
        self._module_to_file = module_to_file or {}
        self._func_defs: dict[str, tuple[str, ast.FunctionDef | ast.AsyncFunctionDef]] = {}
        self._classification_cache: dict[str, DependencyClassification] = {}
        self._build_func_index()

    def _build_func_index(self) -> None:
        for file_str, (_, tree) in self._file_asts.items():
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    self._func_defs[node.name] = (file_str, node)

    def classify_all(self) -> dict[str, DependencyClassification]:
        results: dict[str, DependencyClassification] = {}
        for func_name in self._func_defs:
            results[func_name] = self.classify(func_name)
        return results

    def classify(self, func_name: str, *, _depth: int = 0) -> DependencyClassification:
        if func_name in self._classification_cache:
            return self._classification_cache[func_name]

        if _depth > 5:
            return DependencyClassification(
                func_name=func_name, file="", classification="other",
            )

        entry = self._func_defs.get(func_name)
        if not entry:
            return DependencyClassification(
                func_name=func_name, file="", classification="other",
            )

        file_str, node = entry
        result = DependencyClassification(func_name=func_name, file=file_str, classification="other")

        # Analyze the function body
        result.raises_401 = self._raises_status(node, 401)
        result.raises_403 = self._raises_status(node, 403)
        result.reads_token = self._reads_token(node)
        result.checks_role = self._checks_role(node)
        result.filters_by_user = self._filters_by_user(node)

        # Find inner Depends() calls
        result.inner_deps = self._find_inner_depends(node)

        # Recursively classify inner dependencies
        inner_classifications: list[DependencyClassification] = []
        for dep in result.inner_deps:
            inner = self.classify(dep, _depth=_depth + 1)
            inner_classifications.append(inner)

        # Determine classification based on behavior
        is_auth = (
            result.raises_401
            or result.reads_token
            or self._uses_auth_scheme(node)
            or any(ic.classification == "auth" for ic in inner_classifications)
        )
        is_authz = (
            result.raises_403
            or result.checks_role
            or any(ic.classification == "authz" for ic in inner_classifications)
        )

        if is_authz:
            result.classification = "authz"
            if result.checks_role:
                result.sub_type = "rbac"
        elif is_auth:
            result.classification = "auth"
            uses_auth = self._uses_auth_scheme(node)
            if result.raises_401 and not result.reads_token and not uses_auth:
                result.sub_type = "service_token"
            else:
                result.sub_type = self._detect_auth_mechanism(node, inner_classifications)
        elif result.filters_by_user:
            result.classification = "ownership"
            result.sub_type = "tenant_scope"
        elif self._is_db_dependency(node):
            result.classification = "db"

        self._classification_cache[func_name] = result
        return result

    def classify_endpoint_deps(self, dependencies: list[str]) -> list[str]:
        """Classify a list of endpoint dependency strings and return classifications.

        Returns labels like "auth:jwt_bearer", "authz:rbac", etc.
        """
        classifications: list[str] = []
        for dep_ref in dependencies:
            # dep_ref is "arg_name:func_name" or just "func_name"
            func_name = dep_ref.split(":")[-1].strip()
            if func_name in ("Depends", "Security"):
                continue
            result = self.classify(func_name)
            if result.classification != "other":
                label = result.classification
                if result.sub_type:
                    label = f"{label}:{result.sub_type}"
                classifications.append(label)
        return classifications

    def analyze_middleware(self, middleware_refs: list[str]) -> AuthMiddlewareAnalysis | None:
        """Analyze middleware classes/functions for auth behavior."""
        for ref in middleware_refs:
            ref_lower = ref.lower()
            if not any(kw in ref_lower for kw in ("auth", "jwt", "bearer", "token", "session")):
                continue

            # Look for the middleware class definition
            for file_str, (_, tree) in self._file_asts.items():
                for node in ast.walk(tree):
                    if isinstance(node, ast.ClassDef) and node.name == ref:
                        return self._analyze_middleware_class(node, file_str)
                    if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)) and node.name == ref:
                        return self._analyze_middleware_func(node, file_str)

        return None

    def _analyze_middleware_class(
        self, class_node: ast.ClassDef, file_str: str,
    ) -> AuthMiddlewareAnalysis:
        result = AuthMiddlewareAnalysis(
            middleware_name=class_node.name,
            mechanism="unknown",
        )

        for node in ast.walk(class_node):
            # Detect JWT mechanism
            if isinstance(node, ast.Call):
                call_name = self._resolve_name(node.func)
                if any(kw in call_name.lower() for kw in ("jwt.decode", "decode_token", "jwt_decode")):
                    result.mechanism = "jwt_bearer"
                if "httpbearer" in call_name.lower() or "oauth2passwordbearer" in call_name.lower():
                    result.mechanism = "jwt_bearer"

            # Detect request.state assignment
            if isinstance(node, ast.Assign):
                for target in node.targets:
                    if isinstance(target, ast.Attribute):
                        if isinstance(target.value, ast.Attribute):
                            if target.value.attr == "state":
                                result.sets_request_state = True

            # Detect public paths list
            if isinstance(node, (ast.Assign, ast.AnnAssign)):
                target = node.targets[0] if isinstance(node, ast.Assign) else node.target
                if isinstance(target, ast.Name) and "public" in target.id.lower():
                    value = node.value if isinstance(node, ast.Assign) else node.value
                    if value and isinstance(value, (ast.List, ast.Tuple, ast.Set)):
                        for elt in value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                result.public_paths.append(elt.value)

            # Detect WebSocket exclusion
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                if "ws" in node.value.lower() or "websocket" in node.value.lower():
                    result.websocket_excluded = True

        # Detect token reading from headers
        has_auth_header = False
        for node in ast.walk(class_node):
            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value.lower()
                if val in ("authorization", "bearer", "x-auth-token"):
                    has_auth_header = True

        if has_auth_header and result.mechanism == "unknown":
            result.mechanism = "jwt_bearer"

        return result

    def _analyze_middleware_func(
        self, func_node: ast.FunctionDef | ast.AsyncFunctionDef, file_str: str,
    ) -> AuthMiddlewareAnalysis:
        result = AuthMiddlewareAnalysis(
            middleware_name=func_node.name,
            mechanism="unknown",
        )

        for node in ast.walk(func_node):
            if isinstance(node, ast.Call):
                call_name = self._resolve_name(node.func)
                if any(kw in call_name.lower() for kw in ("jwt.decode", "decode_token")):
                    result.mechanism = "jwt_bearer"

            if isinstance(node, ast.Constant) and isinstance(node.value, str):
                val = node.value.lower()
                if val in ("authorization", "bearer"):
                    result.mechanism = "jwt_bearer"

        return result

    # ── AST analysis helpers ─────────────────────────────────────────────

    def _raises_status(self, node: ast.AST, status_code: int) -> bool:
        for child in ast.walk(node):
            if not isinstance(child, ast.Raise):
                continue
            if child.exc is None:
                continue
            exc = child.exc
            if isinstance(exc, ast.Call):
                for kw in exc.keywords:
                    if kw.arg != "status_code":
                        continue
                    if isinstance(kw.value, ast.Constant):
                        if kw.value.value == status_code:
                            return True
                    elif isinstance(kw.value, ast.Attribute):
                        attr_name = kw.value.attr.lower()
                        if status_code == 401 and ("401" in attr_name or "unauthorized" in attr_name):
                            return True
                        if status_code == 403 and ("403" in attr_name or "forbidden" in attr_name):
                            return True
                if exc.args:
                    first_arg = exc.args[0]
                    if isinstance(first_arg, ast.Constant) and first_arg.value == status_code:
                        return True
                    if isinstance(first_arg, ast.Attribute):
                        attr_name = first_arg.attr.lower()
                        if status_code == 401 and "unauthorized" in attr_name:
                            return True
                        if status_code == 403 and "forbidden" in attr_name:
                            return True
        return False

    def _reads_token(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._resolve_name(child.func).lower()
                if any(kw in name for kw in (
                    "jwt.decode", "decode_token", "verify_token",
                    "httpbearer", "oauth2passwordbearer", "get_token",
                )):
                    return True
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                val = child.value.lower()
                if val in ("authorization", "bearer"):
                    return True
        return False

    def _uses_auth_scheme(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._resolve_name(child.func)
                if any(scheme in name.lower() for scheme in (
                    "httpbearer", "httpbasic", "oauth2passwordbearer",
                    "oauth2authorizationcode", "apikeycookie", "apikeyheader",
                    "apikeyquery",
                )):
                    return True
        return False

    def _checks_role(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Attribute):
                if child.attr in ("role", "roles", "is_admin", "is_superuser"):
                    return True
            if isinstance(child, ast.Subscript):
                if isinstance(child.slice, ast.Constant):
                    if child.slice.value in ("role", "roles"):
                        return True
            if isinstance(child, ast.Compare):
                for comparator in child.comparators:
                    if isinstance(comparator, ast.Constant) and isinstance(comparator.value, str):
                        if comparator.value.lower() in ("admin", "superuser", "staff", "manager"):
                            return True
        return False

    def _filters_by_user(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.keyword) and child.arg:
                if child.arg in ("user_id", "owner_id", "tenant_id", "org_id", "organization_id"):
                    return True
            if isinstance(child, ast.Compare):
                for elem in [child.left, *child.comparators]:
                    if isinstance(elem, ast.Attribute):
                        if elem.attr in ("user_id", "owner_id", "tenant_id", "org_id"):
                            return True
        return False

    def _is_db_dependency(self, node: ast.AST) -> bool:
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._resolve_name(child.func).lower()
                if any(kw in name for kw in ("session", "engine", "connection", "database")):
                    return True
        return False

    def _find_inner_depends(self, node: ast.AST) -> list[str]:
        deps: list[str] = []
        for child in ast.walk(node):
            if not isinstance(child, ast.Call):
                continue
            func_name = self._resolve_name(child.func)
            if func_name.endswith(("Depends", "Security")):
                if child.args:
                    dep = self._resolve_name(child.args[0])
                    if dep and dep not in ("Depends", "Security"):
                        deps.append(dep)
        return deps

    def _detect_auth_mechanism(
        self,
        node: ast.AST,
        inner_classifications: list[DependencyClassification],
    ) -> str:
        # Check for JWT-specific patterns in this function
        for child in ast.walk(node):
            if isinstance(child, ast.Call):
                name = self._resolve_name(child.func).lower()
                if "jwt" in name or "httpbearer" in name or "oauth2password" in name:
                    return "jwt_bearer"
            if isinstance(child, ast.Constant) and isinstance(child.value, str):
                val = child.value.lower()
                if val == "bearer" or "jwt" in val:
                    return "jwt_bearer"

        # Inherit from inner deps
        for ic in inner_classifications:
            if ic.sub_type and ic.sub_type.startswith("jwt"):
                return "jwt_bearer"
            if ic.reads_token:
                return "jwt_bearer"

        return "unknown"

    def _resolve_name(self, node: ast.AST | None) -> str:
        if node is None:
            return ""
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            left = self._resolve_name(node.value)
            return f"{left}.{node.attr}" if left else node.attr
        if isinstance(node, ast.Call):
            return self._resolve_name(node.func)
        return ""
