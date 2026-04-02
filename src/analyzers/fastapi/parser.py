from __future__ import annotations

import ast
import re
from pathlib import Path

from src.observability.logging.setup import get_logger
from src.schemas.internal import BackendEndpoint, FastAPIGlobalFacts, SchemaField, StaticAnalysisResult

logger = get_logger(__name__)

IGNORED_DIRS = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__", ".pytest_cache"}
HTTP_DECORATORS = {"get", "post", "put", "patch", "delete", "options", "head"}
ENV_PATTERN = re.compile(r"os\.(?:getenv|environ\.get)\(\s*['\"]([A-Z0-9_]+)['\"]")
ENV_PATTERN_ALT = re.compile(r"os\.environ\[['\"]([A-Z0-9_]+)['\"]\]")
URL_PATTERN = re.compile(r"https?://[^'\"\s)]+")


class FastAPIParser:
    def parse(self, repo_name: str, repo_path: Path) -> StaticAnalysisResult:
        endpoints: list[BackendEndpoint] = []
        env_references: set[str] = set()
        hardcoded_urls: set[str] = set()
        parser_errors: list[str] = []

        middleware_refs: set[str] = set()
        exception_handler_refs: set[str] = set()
        global_dependencies: set[str] = set()
        module_call_refs: set[str] = set()

        for file_path in self._iter_py_files(repo_path):
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                module_tree = ast.parse(content)
            except (SyntaxError, UnicodeDecodeError) as exc:
                parser_errors.append(f"{file_path}: {exc}")
                continue

            env_references.update(ENV_PATTERN.findall(content))
            env_references.update(ENV_PATTERN_ALT.findall(content))
            hardcoded_urls.update(URL_PATTERN.findall(content))

            try:
                module_endpoints, module_facts = self._parse_module(repo_name, repo_path, file_path, module_tree)
                endpoints.extend(module_endpoints)
                middleware_refs.update(module_facts.middleware_refs)
                exception_handler_refs.update(module_facts.exception_handler_refs)
                global_dependencies.update(module_facts.global_dependencies)
                module_call_refs.update(module_facts.module_call_refs)
            except Exception as exc:  # noqa: BLE001
                logger.exception("fastapi_module_parse_failed file=%s", file_path, extra={"request_id": "-"})
                parser_errors.append(f"{file_path}: parser failure {exc}")

        return StaticAnalysisResult(
            repo=repo_name,
            backend_endpoints=endpoints,
            env_references=sorted(env_references),
            hardcoded_urls=sorted(hardcoded_urls),
            parser_errors=parser_errors,
            fastapi_facts=FastAPIGlobalFacts(
                middleware_refs=sorted(middleware_refs),
                exception_handler_refs=sorted(exception_handler_refs),
                global_dependencies=sorted(global_dependencies),
                module_call_refs=sorted(module_call_refs),
            ),
        )

    def _parse_module(
        self,
        repo_name: str,
        repo_path: Path,
        file_path: Path,
        tree: ast.Module,
    ) -> tuple[list[BackendEndpoint], FastAPIGlobalFacts]:
        pydantic_models = self._collect_pydantic_models(tree)
        router_prefixes, router_dependencies, app_names, app_dependencies = self._collect_router_and_app_info(tree)
        self._augment_router_info_from_includes(tree, router_prefixes, router_dependencies)

        endpoints: list[BackendEndpoint] = []
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            endpoints.extend(
                self._extract_endpoints_from_function(
                    repo_name=repo_name,
                    repo_path=repo_path,
                    file_path=file_path,
                    node=node,
                    pydantic_models=pydantic_models,
                    router_prefixes=router_prefixes,
                    router_dependencies=router_dependencies,
                    app_names=app_names,
                    app_dependencies=app_dependencies,
                )
            )

        module_facts = FastAPIGlobalFacts(
            middleware_refs=sorted(self._collect_middleware_refs(tree)),
            exception_handler_refs=sorted(self._collect_exception_handler_refs(tree)),
            global_dependencies=sorted(
                set(app_dependencies + [dep for deps in router_dependencies.values() for dep in deps])
            ),
            module_call_refs=sorted(self._collect_module_call_refs(tree)),
        )

        return endpoints, module_facts

    def _collect_router_and_app_info(
        self,
        tree: ast.Module,
    ) -> tuple[dict[str, str], dict[str, list[str]], set[str], list[str]]:
        router_prefixes: dict[str, str] = {}
        router_dependencies: dict[str, list[str]] = {}
        app_names: set[str] = set()
        app_dependencies: list[str] = []

        for node in tree.body:
            if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                continue
            if not node.targets:
                continue
            if not isinstance(node.targets[0], ast.Name):
                continue

            target_name = node.targets[0].id
            func_name = self._resolve_name(node.value.func)
            dependencies = self._extract_dependencies_from_keyword(node.value.keywords, "dependencies")

            if func_name.endswith("APIRouter"):
                prefix = self._extract_keyword_str(node.value.keywords, "prefix") or ""
                router_prefixes[target_name] = prefix
                router_dependencies[target_name] = dependencies
            elif func_name.endswith("FastAPI"):
                app_names.add(target_name)
                app_dependencies.extend(dependencies)

        return router_prefixes, router_dependencies, app_names, sorted(set(app_dependencies))

    def _augment_router_info_from_includes(
        self,
        tree: ast.Module,
        router_prefixes: dict[str, str],
        router_dependencies: dict[str, list[str]],
    ) -> None:
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "include_router" or not node.args:
                continue

            router_arg = node.args[0]
            if not isinstance(router_arg, ast.Name):
                continue

            include_prefix = self._extract_keyword_str(node.keywords, "prefix") or ""
            include_dependencies = self._extract_dependencies_from_keyword(node.keywords, "dependencies")

            if include_prefix:
                current = router_prefixes.get(router_arg.id, "")
                router_prefixes[router_arg.id] = f"{include_prefix}{current}"

            if include_dependencies:
                current_deps = router_dependencies.get(router_arg.id, [])
                router_dependencies[router_arg.id] = sorted(set(current_deps + include_dependencies))

    def _collect_pydantic_models(self, tree: ast.Module) -> dict[str, list[SchemaField]]:
        models: dict[str, list[SchemaField]] = {}
        for node in tree.body:
            if not isinstance(node, ast.ClassDef):
                continue
            if not self._inherits_from_base_model(node):
                continue
            fields: list[SchemaField] = []
            for child in node.body:
                if not isinstance(child, ast.AnnAssign) or not isinstance(child.target, ast.Name):
                    continue
                field_name = child.target.id
                field_type = self._annotation_to_str(child.annotation)
                required = child.value is None and not self._annotation_is_optional(child.annotation)
                fields.append(SchemaField(name=field_name, field_type=field_type, required=required))
            models[node.name] = fields
        return models

    def _inherits_from_base_model(self, class_def: ast.ClassDef) -> bool:
        for base in class_def.bases:
            base_name = self._resolve_name(base)
            if base_name.endswith("BaseModel"):
                return True
        return False

    def _extract_endpoints_from_function(
        self,
        repo_name: str,
        repo_path: Path,
        file_path: Path,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        pydantic_models: dict[str, list[SchemaField]],
        router_prefixes: dict[str, str],
        router_dependencies: dict[str, list[str]],
        app_names: set[str],
        app_dependencies: list[str],
    ) -> list[BackendEndpoint]:
        extracted: list[BackendEndpoint] = []

        request_schema, request_fields = self._extract_request_schema(node, pydantic_models)
        arg_dependencies = self._extract_dependencies_from_args(node)
        call_refs = self._extract_call_refs(node)
        string_refs = self._extract_string_refs(node)
        wrapper_decorators = self._extract_non_route_decorators(node.decorator_list)
        has_try_except = self._contains_try_except(node)

        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue

            decorated_object = decorator.func.value
            if not isinstance(decorated_object, ast.Name):
                continue
            decorated_name = decorated_object.id

            method_candidates: list[str] = []
            if decorator.func.attr in HTTP_DECORATORS:
                method_candidates = [decorator.func.attr.upper()]
            elif decorator.func.attr == "api_route":
                method_candidates = self._extract_api_route_methods(decorator)

            if not method_candidates:
                continue
            if decorated_name not in router_prefixes and decorated_name not in app_names:
                continue

            route_path = self._extract_route_path(decorator)
            route_prefix = router_prefixes.get(decorated_name, "")
            full_path = self._normalize_path(f"{route_prefix}{route_path}")

            response_schema = self._extract_response_schema(decorator)
            response_fields = pydantic_models.get(response_schema, []) if response_schema else []
            decorator_dependencies = self._extract_dependencies_from_decorator(decorator)
            scoped_dependencies = list(arg_dependencies + decorator_dependencies)

            if decorated_name in router_dependencies:
                scoped_dependencies.extend(router_dependencies[decorated_name])
            if decorated_name in app_names:
                scoped_dependencies.extend(app_dependencies)

            rel_file = str(file_path.relative_to(repo_path))
            line_number = getattr(decorator, "lineno", None) or getattr(node, "lineno", None)

            for method in method_candidates:
                extracted.append(
                    BackendEndpoint(
                        service=repo_name,
                        file=rel_file,
                        line=line_number,
                        path=full_path,
                        method=method,
                        request_schema=request_schema,
                        request_fields=request_fields,
                        response_schema=response_schema,
                        response_fields=response_fields,
                        dependencies=sorted(set(scoped_dependencies)),
                        function_name=node.name,
                        decorators=wrapper_decorators,
                        call_refs=call_refs,
                        string_refs=string_refs,
                        has_try_except=has_try_except,
                    )
                )

        return extracted

    def _extract_request_schema(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        pydantic_models: dict[str, list[SchemaField]],
    ) -> tuple[str | None, list[SchemaField]]:
        for arg in node.args.args + node.args.kwonlyargs:
            if arg.arg in {"self", "request", "response", "background_tasks"}:
                continue
            if arg.annotation is None:
                continue
            annotation = self._annotation_to_str(arg.annotation)
            if annotation in pydantic_models:
                return annotation, pydantic_models[annotation]
        return None, []

    def _extract_dependencies_from_args(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        dependencies: list[str] = []

        defaults = list(node.args.defaults)
        arg_with_defaults = node.args.args[-len(defaults) :] if defaults else []
        for arg, default in zip(arg_with_defaults, defaults, strict=False):
            if isinstance(default, ast.Call) and self._resolve_name(default.func).endswith("Depends"):
                dependency_name = self._resolve_name(default.args[0]) if default.args else "Depends"
                dependencies.append(f"{arg.arg}:{dependency_name}")

        kw_defaults = node.args.kw_defaults
        for arg, default in zip(node.args.kwonlyargs, kw_defaults, strict=False):
            if isinstance(default, ast.Call) and self._resolve_name(default.func).endswith("Depends"):
                dependency_name = self._resolve_name(default.args[0]) if default.args else "Depends"
                dependencies.append(f"{arg.arg}:{dependency_name}")

        return dependencies

    def _extract_dependencies_from_decorator(self, decorator: ast.Call) -> list[str]:
        return self._extract_dependencies_from_keyword(decorator.keywords, "dependencies")

    def _extract_dependencies_from_keyword(self, keywords: list[ast.keyword], key_name: str) -> list[str]:
        dependencies: list[str] = []
        for kw in keywords:
            if kw.arg != key_name:
                continue
            if not isinstance(kw.value, (ast.List, ast.Tuple)):
                continue
            for item in kw.value.elts:
                if not isinstance(item, ast.Call):
                    continue
                if not self._resolve_name(item.func).endswith("Depends"):
                    continue
                dependency_name = self._resolve_name(item.args[0]) if item.args else "Depends"
                dependencies.append(dependency_name)
        return dependencies

    def _extract_non_route_decorators(self, decorators: list[ast.expr]) -> list[str]:
        names: list[str] = []
        for decorator in decorators:
            if isinstance(decorator, ast.Call):
                if isinstance(decorator.func, ast.Attribute) and decorator.func.attr in HTTP_DECORATORS.union({"api_route"}):
                    continue
                names.append(self._resolve_name(decorator.func))
                continue
            names.append(self._resolve_name(decorator))
        return sorted(set(filter(None, names)))

    def _extract_call_refs(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        refs: set[str] = set()
        for item in ast.walk(node):
            if isinstance(item, ast.Call):
                call_name = self._resolve_name(item.func)
                if call_name:
                    refs.add(call_name)
        return sorted(refs)

    def _extract_string_refs(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        refs: set[str] = set()
        for item in ast.walk(node):
            if isinstance(item, ast.Constant) and isinstance(item.value, str):
                value = item.value.strip()
                if not value or len(value) > 80:
                    continue
                refs.add(value)
        return sorted(refs)

    def _contains_try_except(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        return any(isinstance(item, ast.Try) for item in ast.walk(node))

    def _collect_middleware_refs(self, tree: ast.Module) -> set[str]:
        refs: set[str] = set()
        for node in tree.body:
            if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                for decorator in node.decorator_list:
                    if isinstance(decorator, ast.Call) and isinstance(decorator.func, ast.Attribute):
                        if decorator.func.attr == "middleware":
                            refs.add(node.name)

        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "add_middleware":
                continue
            if node.args:
                refs.add(self._resolve_name(node.args[0]))
            refs.add("add_middleware")

        return refs

    def _collect_exception_handler_refs(self, tree: ast.Module) -> set[str]:
        refs: set[str] = set()
        for node in tree.body:
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            for decorator in node.decorator_list:
                if not isinstance(decorator, ast.Call):
                    continue
                if not isinstance(decorator.func, ast.Attribute):
                    continue
                if decorator.func.attr != "exception_handler":
                    continue
                refs.add(node.name)
                refs.add("exception_handler")
                if decorator.args:
                    refs.add(self._resolve_name(decorator.args[0]))
        return refs

    def _collect_module_call_refs(self, tree: ast.Module) -> set[str]:
        refs: set[str] = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call):
                call_name = self._resolve_name(node.func)
                if call_name:
                    refs.add(call_name)
        return refs

    def _extract_route_path(self, decorator: ast.Call) -> str:
        if decorator.args and isinstance(decorator.args[0], ast.Constant) and isinstance(decorator.args[0].value, str):
            return decorator.args[0].value
        path_kw = self._extract_keyword_str(decorator.keywords, "path")
        return path_kw or ""

    def _extract_response_schema(self, decorator: ast.Call) -> str | None:
        for kw in decorator.keywords:
            if kw.arg == "response_model":
                return self._annotation_to_str(kw.value)
        return None

    def _extract_api_route_methods(self, decorator: ast.Call) -> list[str]:
        for kw in decorator.keywords:
            if kw.arg != "methods" or not isinstance(kw.value, (ast.List, ast.Tuple)):
                continue
            methods: list[str] = []
            for item in kw.value.elts:
                if isinstance(item, ast.Constant) and isinstance(item.value, str):
                    methods.append(item.value.upper())
            return methods
        return ["GET"]

    def _annotation_to_str(self, node: ast.AST) -> str:
        if isinstance(node, ast.Name):
            return node.id
        if isinstance(node, ast.Attribute):
            left = self._annotation_to_str(node.value)
            return f"{left}.{node.attr}" if left else node.attr
        if isinstance(node, ast.Subscript):
            root = self._annotation_to_str(node.value)
            sub = self._annotation_to_str(node.slice)
            return f"{root}[{sub}]"
        if isinstance(node, ast.Tuple):
            return ",".join(self._annotation_to_str(part) for part in node.elts)
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.BitOr):
            left = self._annotation_to_str(node.left)
            right = self._annotation_to_str(node.right)
            return f"{left}|{right}"
        if isinstance(node, ast.Constant):
            return str(node.value)
        return "unknown"

    def _annotation_is_optional(self, node: ast.AST) -> bool:
        annotation = self._annotation_to_str(node)
        return "Optional[" in annotation or "|None" in annotation or "None|" in annotation

    def _extract_keyword_str(self, keywords: list[ast.keyword], name: str) -> str | None:
        for kw in keywords:
            if kw.arg == name and isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, str):
                return kw.value.value
        return None

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
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return node.value
        return ""

    def _normalize_path(self, path: str) -> str:
        if not path:
            return "/"
        normalized = re.sub(r"/{2,}", "/", path)
        return normalized if normalized.startswith("/") else f"/{normalized}"

    def _iter_py_files(self, repo_path: Path) -> list[Path]:
        files: list[Path] = []
        for path in repo_path.rglob("*.py"):
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            files.append(path)
        return files
