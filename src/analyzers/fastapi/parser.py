from __future__ import annotations

import ast
import re
from pathlib import Path

from src.analyzers.fastapi.dependency_analyzer import DependencyAnalyzer
from src.analyzers.fastapi.service_call_tracer import ServiceCallTracer
from src.observability.logging.setup import get_logger
from src.schemas.internal import (
    AuthMiddlewareAnalysisResult,
    BackendEndpoint,
    CorsConfig,
    FastAPIGlobalFacts,
    SchemaField,
    StaticAnalysisResult,
)

logger = get_logger(__name__)

IGNORED_DIRS = {".git", "node_modules", "dist", "build", ".venv", "venv", "__pycache__", ".pytest_cache"}
HTTP_DECORATORS = {"get", "post", "put", "patch", "delete", "options", "head"}
WEBSOCKET_DECORATORS = {"websocket", "websocket_route"}

# FastAPI parameter kinds that are NOT request-body fields.
# Args carrying any of these as their default value should be skipped when
# extracting the request schema so that auth/query/header dependencies are
# not mistaken for body fields.
_FASTAPI_NON_BODY_DEFAULTS: frozenset[str] = frozenset(
    {"Depends", "Header", "Cookie", "Query", "Path", "Security", "File", "Form"}
)

# Argument names that are never part of the business payload regardless of
# their annotation type.
_SKIP_ARG_NAMES: frozenset[str] = frozenset(
    {"self", "request", "response", "background_tasks", "db", "session", "conn", "transaction"}
)
ENV_PATTERN = re.compile(r"os\.(?:getenv|environ\.get)\(\s*['\"]([A-Z0-9_]+)['\"]")
ENV_PATTERN_ALT = re.compile(r"os\.environ\[['\"]([A-Z0-9_]+)['\"]\]")
URL_PATTERN = re.compile(r"https?://[^'\"\s)]+")

_NON_CONFIG_URL_HOSTS: frozenset[str] = frozenset({
    "w3.org", "schema.org", "json-schema.org", "purl.org",
    "openid.net", "xml.org", "xmlsoap.org", "xmlns.com",
    "relaxng.org", "mozilla.org/MPL", "creativecommons.org",
    "spdx.org", "semver.org",
})

# Max iterations for resolving chained include_router prefix chains (prevents infinite loops)
_MAX_CHAIN_DEPTH = 8

# Common top-level source packages to strip when building module-to-file maps
_SRC_ROOTS = {"src", "app", "api", "backend", "server", "core", "application"}

# Subscript wrappers that can wrap a response model type
_SUBSCRIPT_WRAPPER_RE = re.compile(r"^(?:List|Optional|Union|Set|Tuple|Sequence|Page)\[(\w+)")


class FastAPIParser:
    """
    Two-phase parser for FastAPI projects.

    Phase 1 – repo-wide context:
      • Parse every .py file into an AST once.
      • Build a global Pydantic BaseModel registry (all models across all files).
      • Build a cross-file router-prefix map by resolving APIRouter definitions,
        import statements, and include_router() call chains.

    Phase 2 – endpoint extraction:
      • Walk the full AST of each file (not just top-level) to find every
        function/method decorated with an HTTP verb on a known router/app.
      • Apply the resolved prefixes from Phase 1 to produce correct full paths.
    """

    def parse(self, repo_name: str, repo_path: Path) -> tuple[StaticAnalysisResult, dict[str, tuple[Path, ast.Module]]]:
        endpoints: list[BackendEndpoint] = []
        env_references: set[str] = set()
        hardcoded_urls: set[str] = set()
        configurable_urls: set[str] = set()
        parser_errors: list[str] = []

        middleware_refs: set[str] = set()
        exception_handler_refs: set[str] = set()
        global_dependencies: set[str] = set()
        module_call_refs: set[str] = set()
        merged_cors_config: CorsConfig | None = None

        # ── Phase 1a: collect ASTs ──────────────────────────────────────────
        file_asts: dict[str, tuple[Path, ast.Module]] = {}
        for file_path in self._iter_py_files(repo_path):
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
                tree = ast.parse(content)
            except (SyntaxError, UnicodeDecodeError) as exc:
                parser_errors.append(f"{file_path}: {exc}")
                continue

            env_references.update(ENV_PATTERN.findall(content))
            file_urls = set(URL_PATTERN.findall(content))
            filtered_urls = {u for u in file_urls if not self._is_non_config_url(u)}
            settings_urls = self._collect_base_settings_urls(tree, content)
            configurable_urls.update(settings_urls)
            hardcoded_urls.update(filtered_urls - settings_urls)
            env_references.update(ENV_PATTERN_ALT.findall(content))
            file_asts[str(file_path)] = (file_path, tree)

        # ── Phase 1b: build cross-file context ─────────────────────────────
        global_models = self._build_global_pydantic_models(file_asts)
        orm_models = self._build_global_orm_models(file_asts)
        annotated_deps_map = self._build_annotated_type_alias_map(file_asts)
        module_to_file = self._build_module_to_file_map(repo_path)
        cross_file_info = self._build_cross_file_router_info(file_asts, module_to_file)

        # ── Phase 2: extract endpoints from every file ──────────────────────
        for file_str, (file_path, tree) in file_asts.items():
            try:
                router_prefixes, router_deps, app_names, app_deps = cross_file_info.get(
                    file_str, ({}, {}, set(), [])
                )
                module_endpoints, module_facts = self._parse_module(
                    repo_name=repo_name,
                    repo_path=repo_path,
                    file_path=file_path,
                    tree=tree,
                    pydantic_models=global_models,
                    annotated_deps_map=annotated_deps_map,
                    router_prefixes=router_prefixes,
                    router_dependencies=router_deps,
                    app_names=app_names,
                    app_dependencies=app_deps,
                )
                endpoints.extend(module_endpoints)
                middleware_refs.update(module_facts.middleware_refs)
                exception_handler_refs.update(module_facts.exception_handler_refs)
                global_dependencies.update(module_facts.global_dependencies)
                module_call_refs.update(module_facts.module_call_refs)
                if module_facts.cors_config and merged_cors_config is None:
                    merged_cors_config = module_facts.cors_config
            except Exception as exc:  # noqa: BLE001
                logger.exception("fastapi_module_parse_failed file=%s", file_path, extra={"request_id": "-"})
                parser_errors.append(f"{file_path}: parser failure {exc}")

        # ── Phase 1c: AST-based dependency classification ────────────────
        dep_analyzer = DependencyAnalyzer(file_asts, module_to_file)
        for ep in endpoints:
            ep.dep_classifications = dep_analyzer.classify_endpoint_deps(ep.dependencies)
            auth_mechs = [
                dc.split(":", 1)[1]
                for dc in ep.dep_classifications
                if dc.startswith("auth:") and ":" in dc
            ]
            if auth_mechs:
                ep.auth_mechanism_detected = auth_mechs[0]

        # ── Phase 1d: service call-chain tracing ─────────────────────────
        call_tracer = ServiceCallTracer(file_asts, module_to_file)
        handler_nodes = self._collect_handler_nodes(file_asts, endpoints)
        for ep, handler_node in handler_nodes:
            if handler_node is not None:
                ep.service_call_signals = call_tracer.trace_handler_calls(handler_node)

        # ── Phase 1e: detect ORM model used as response_model ────────────
        for ep in endpoints:
            if ep.response_schema:
                response_base = self._base_model_name(ep.response_schema)
                if response_base in orm_models:
                    ep.orm_model_used = response_base

        # Analyze middleware for auth behaviour
        auth_mw_analysis: AuthMiddlewareAnalysisResult | None = None
        mw_analysis_raw = dep_analyzer.analyze_middleware(sorted(middleware_refs))
        if mw_analysis_raw:
            auth_mw_analysis = AuthMiddlewareAnalysisResult(
                middleware_name=mw_analysis_raw.middleware_name,
                mechanism=mw_analysis_raw.mechanism,
                public_paths=mw_analysis_raw.public_paths,
                websocket_excluded=mw_analysis_raw.websocket_excluded,
                sets_request_state=mw_analysis_raw.sets_request_state,
            )

        result = StaticAnalysisResult(
            repo=repo_name,
            backend_endpoints=endpoints,
            env_references=sorted(env_references),
            hardcoded_urls=sorted(hardcoded_urls),
            configurable_urls=sorted(configurable_urls),
            parser_errors=parser_errors,
            fastapi_facts=FastAPIGlobalFacts(
                middleware_refs=sorted(middleware_refs),
                exception_handler_refs=sorted(exception_handler_refs),
                global_dependencies=sorted(global_dependencies),
                module_call_refs=sorted(module_call_refs),
                cors_config=merged_cors_config,
                auth_middleware_analysis=auth_mw_analysis,
            ),
            orm_model_registry=orm_models,
        )
        return result, file_asts

    # ──────────────────────────────────────────────────────────────────────────
    # Phase 1 – repo-wide context builders
    # ──────────────────────────────────────────────────────────────────────────

    def _build_global_pydantic_models(
        self,
        file_asts: dict[str, tuple[Path, ast.Module]],
    ) -> dict[str, list[SchemaField]]:
        """
        Build a repo-wide name → fields map for every Pydantic BaseModel subclass.

        When two files define a class with the same name the later-parsed one wins.
        Class-name collisions within a single project are rare and this is still
        far more accurate than only looking at same-file models.
        """
        models: dict[str, list[SchemaField]] = {}
        for _file_str, (_, tree) in file_asts.items():
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

    def _build_annotated_type_alias_map(
        self,
        file_asts: dict[str, tuple[Path, ast.Module]],
    ) -> dict[str, list[str]]:
        """Build a repo-wide map of type aliases that wrap Annotated[T, Depends(func)].

        Handles patterns like:
            CurrentUserID = Annotated[str, Depends(get_current_user_id)]
            TicketServiceDep = Annotated[TicketService, Depends(get_ticket_service)]
        """
        alias_map: dict[str, list[str]] = {}
        for _file_str, (_, tree) in file_asts.items():
            for node in tree.body:
                if not isinstance(node, ast.Assign) or len(node.targets) != 1:
                    continue
                target = node.targets[0]
                if not isinstance(target, ast.Name):
                    continue
                deps = self._extract_deps_from_annotated(node.value)
                if deps:
                    alias_map[target.id] = deps
        return alias_map

    def _extract_deps_from_annotated(self, node: ast.expr) -> list[str]:
        """Extract Depends() function names from an Annotated[T, Depends(func), ...] node."""
        if not isinstance(node, ast.Subscript):
            return []
        base_name = self._resolve_name(node.value)
        if not base_name.endswith("Annotated"):
            return []
        if not isinstance(node.slice, ast.Tuple):
            return []
        deps: list[str] = []
        for item in node.slice.elts[1:]:
            if isinstance(item, ast.Call) and self._resolve_name(item.func).endswith("Depends"):
                dep_name = self._resolve_name(item.args[0]) if item.args else "Depends"
                deps.append(dep_name)
        return deps

    def _build_module_to_file_map(self, repo_path: Path) -> dict[str, str]:
        """
        Map every Python module's dotted name to its absolute file path.

        Generates both the full path (e.g. ``src.api.routes.users``) and stripped
        variants that drop common root packages (e.g. ``api.routes.users``,
        ``routes.users``), so both absolute and project-relative imports resolve.
        """
        module_map: dict[str, str] = {}
        for py_file in self._iter_py_files(repo_path):
            try:
                rel = py_file.relative_to(repo_path)
            except ValueError:
                continue
            parts = list(rel.with_suffix("").parts)
            if parts and parts[-1] == "__init__":
                parts = parts[:-1]
            if not parts:
                continue
            file_str = str(py_file)
            remaining = list(parts)
            while remaining:
                module_map[".".join(remaining)] = file_str
                if remaining[0] in _SRC_ROOTS:
                    remaining = remaining[1:]
                else:
                    break
        return module_map

    def _resolve_module_to_file(
        self,
        module: str,
        current_file: str,
        module_to_file: dict[str, str],
    ) -> str | None:
        """
        Resolve a module string from an import statement to an absolute file path.

        Handles:
        - Absolute imports: ``from src.routes.users import router``
        - Stripped imports: ``from routes.users import router``
        - Relative-style strings (leading dots stripped by the ast.ImportFrom node's
          level attribute, but we receive the module string after that):
          ``from .routes import router`` → module = "routes" in the ast node
        """
        if not module:
            return None
        # Direct lookup (covers absolute and stripped forms)
        if module in module_to_file:
            return module_to_file[module]
        # Try common root prefix strips
        for prefix in _SRC_ROOTS:
            candidate = f"{prefix}.{module}"
            if candidate in module_to_file:
                return module_to_file[candidate]
        # Try resolving relative to the current file's package hierarchy
        # e.g., current = /repo/src/api/v1/app.py → try src.api.v1.routes, src.api.routes, etc.
        current_module: str | None = None
        for mod, fpath in module_to_file.items():
            if fpath == current_file:
                current_module = mod
                break
        if current_module:
            parent_parts = current_module.split(".")[:-1]
            for i in range(len(parent_parts), 0, -1):
                candidate = ".".join(parent_parts[:i]) + "." + module
                if candidate in module_to_file:
                    return module_to_file[candidate]
        return None

    def _build_cross_file_router_info(
        self,
        file_asts: dict[str, tuple[Path, ast.Module]],
        module_to_file: dict[str, str],
    ) -> dict[str, tuple[dict[str, str], dict[str, list[str]], set[str], list[str]]]:
        """
        Compute effective router prefixes and dependencies across all files.

        The algorithm:
        1. Collect every ``APIRouter`` / ``FastAPI`` definition and its local prefix/deps.
        2. Collect every import statement so we can resolve ``x`` to its source file.
        3. Collect every ``router.include_router(child, prefix=...)`` call.
        4. Iteratively propagate accumulated prefixes along the include chain until
           stable (handles arbitrary nesting depth up to ``_MAX_CHAIN_DEPTH``).
        5. Return per-file dicts of ``{local_var: effective_prefix}`` ready for
           endpoint extraction.

        Returns
        -------
        dict mapping file_str → (router_prefixes, router_deps, app_names, app_deps)
        """
        # ── Step 1: collect local APIRouter and FastAPI definitions ──────────
        # router_local_prefix[(file, var)] = prefix string
        router_local_prefix: dict[tuple[str, str], str] = {}
        router_local_deps: dict[tuple[str, str], list[str]] = {}
        app_by_file: dict[str, set[str]] = {}
        app_deps_by_file: dict[str, list[str]] = {}

        for file_str, (_, tree) in file_asts.items():
            file_apps: set[str] = set()
            file_app_deps: list[str] = []
            for node in tree.body:
                if not isinstance(node, ast.Assign) or not isinstance(node.value, ast.Call):
                    continue
                if not node.targets or not isinstance(node.targets[0], ast.Name):
                    continue
                target = node.targets[0].id
                func_name = self._resolve_name(node.value.func)
                deps = self._extract_dependencies_from_keyword(node.value.keywords, "dependencies")
                if func_name.endswith("APIRouter"):
                    prefix = self._extract_keyword_str(node.value.keywords, "prefix") or ""
                    router_local_prefix[(file_str, target)] = prefix
                    router_local_deps[(file_str, target)] = deps
                elif func_name.endswith("FastAPI"):
                    file_apps.add(target)
                    file_app_deps.extend(deps)
            app_by_file[file_str] = file_apps
            app_deps_by_file[file_str] = sorted(set(file_app_deps))

        # ── Step 2: collect import maps ──────────────────────────────────────
        # import_by_file[file_str][local_name] = (module_str, original_name)
        import_by_file: dict[str, dict[str, tuple[str, str]]] = {}
        for file_str, (_, tree) in file_asts.items():
            imports: dict[str, tuple[str, str]] = {}
            for node in tree.body:
                if isinstance(node, ast.ImportFrom) and node.module:
                    for alias in node.names:
                        local = alias.asname or alias.name
                        imports[local] = (node.module, alias.name)
                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        local = alias.asname or alias.name
                        imports[local] = (alias.name, alias.name)
            import_by_file[file_str] = imports

        # ── Step 3: collect include_router() calls ────────────────────────────
        # Each entry: (caller_file, parent_var, child_local_name, extra_prefix, extra_deps)
        include_calls: list[tuple[str, str, str, str, list[str]]] = []
        for file_str, (_, tree) in file_asts.items():
            for node in ast.walk(tree):
                if not isinstance(node, ast.Call):
                    continue
                if not isinstance(node.func, ast.Attribute):
                    continue
                if node.func.attr != "include_router" or not node.args:
                    continue
                child_arg = node.args[0]
                if not isinstance(child_arg, ast.Name):
                    continue
                parent_obj = node.func.value
                if not isinstance(parent_obj, ast.Name):
                    continue
                extra_prefix = self._extract_keyword_str(node.keywords, "prefix") or ""
                extra_deps = self._extract_dependencies_from_keyword(node.keywords, "dependencies")
                include_calls.append((file_str, parent_obj.id, child_arg.id, extra_prefix, extra_deps))

        # ── Helper: resolve a local variable name to its defining (file, var) ──
        def resolve_to_def(local_name: str, in_file: str) -> tuple[str | None, str]:
            # Locally defined as a router?
            if (in_file, local_name) in router_local_prefix:
                return in_file, local_name
            # Imported?
            imp = import_by_file.get(in_file, {}).get(local_name)
            if not imp:
                return None, local_name
            module_str, orig_name = imp
            src_file = self._resolve_module_to_file(module_str, in_file, module_to_file)
            if not src_file:
                return None, local_name
            if (src_file, orig_name) in router_local_prefix:
                return src_file, orig_name
            # One level of re-export (e.g., __init__.py re-exports)
            sub_imp = import_by_file.get(src_file, {}).get(orig_name)
            if sub_imp:
                sub_module, sub_orig = sub_imp
                sub_file = self._resolve_module_to_file(sub_module, src_file, module_to_file)
                if sub_file and (sub_file, sub_orig) in router_local_prefix:
                    return sub_file, sub_orig
            return src_file, orig_name

        # ── Step 4: iteratively propagate include_router prefixes ─────────────
        # Start with local prefix as the effective prefix for each router.
        effective_prefix: dict[tuple[str, str], str] = dict(router_local_prefix)
        effective_deps: dict[tuple[str, str], list[str]] = {
            k: list(v) for k, v in router_local_deps.items()
        }

        for _iteration in range(_MAX_CHAIN_DEPTH):
            changed = False
            for caller_file, parent_var, child_local, extra_prefix, extra_deps in include_calls:
                child_def_file, child_def_var = resolve_to_def(child_local, caller_file)
                if child_def_file is None:
                    continue
                child_key = (child_def_file, child_def_var)

                # If the parent itself is an included router, prepend its accumulated prefix.
                parent_def_file, parent_def_var = resolve_to_def(parent_var, caller_file)
                parent_prefix = ""
                if parent_def_file:
                    parent_prefix = effective_prefix.get((parent_def_file, parent_def_var), "")

                # Effective prefix for this child:
                # parent_accumulated + include_extra + child_own_local
                child_own = router_local_prefix.get(child_key, "")
                new_prefix = f"{parent_prefix}{extra_prefix}{child_own}"

                if effective_prefix.get(child_key) != new_prefix:
                    effective_prefix[child_key] = new_prefix
                    changed = True

                new_deps = sorted(set(router_local_deps.get(child_key, []) + extra_deps))
                if effective_deps.get(child_key) != new_deps:
                    effective_deps[child_key] = new_deps

            if not changed:
                break

        # ── Step 5: build per-file result dicts ───────────────────────────────
        result: dict[str, tuple[dict[str, str], dict[str, list[str]], set[str], list[str]]] = {}
        for file_str in file_asts:
            file_router_prefixes: dict[str, str] = {}
            file_router_deps_map: dict[str, list[str]] = {}

            # Locally defined routers
            for (def_file, var_name) in router_local_prefix:
                if def_file != file_str:
                    continue
                key = (file_str, var_name)
                file_router_prefixes[var_name] = effective_prefix.get(key, "")
                file_router_deps_map[var_name] = effective_deps.get(key, [])

            # Imported routers used in this file (e.g., ``@imported_router.get(...)``)
            for local_name, (module_str, orig_name) in import_by_file.get(file_str, {}).items():
                if local_name in file_router_prefixes:
                    continue
                src_file = self._resolve_module_to_file(module_str, file_str, module_to_file)
                if not src_file:
                    continue
                src_key = (src_file, orig_name)
                if src_key in effective_prefix:
                    file_router_prefixes[local_name] = effective_prefix[src_key]
                    file_router_deps_map[local_name] = effective_deps.get(src_key, [])

            result[file_str] = (
                file_router_prefixes,
                file_router_deps_map,
                app_by_file.get(file_str, set()),
                app_deps_by_file.get(file_str, []),
            )

        return result

    # ──────────────────────────────────────────────────────────────────────────
    # Phase 2 – module-level parsing (uses pre-built cross-file context)
    # ──────────────────────────────────────────────────────────────────────────

    def _parse_module(
        self,
        repo_name: str,
        repo_path: Path,
        file_path: Path,
        tree: ast.Module,
        pydantic_models: dict[str, list[SchemaField]],
        annotated_deps_map: dict[str, list[str]],
        router_prefixes: dict[str, str],
        router_dependencies: dict[str, list[str]],
        app_names: set[str],
        app_dependencies: list[str],
    ) -> tuple[list[BackendEndpoint], FastAPIGlobalFacts]:
        endpoints: list[BackendEndpoint] = []

        # Walk the *entire* AST to find endpoint functions regardless of nesting
        # depth.  Functions in nested classes, conditional blocks, and inner
        # scopes are all visited; _extract_endpoints_from_function filters by
        # decorator presence so non-routes are silently ignored.
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            endpoints.extend(
                self._extract_endpoints_from_function(
                    repo_name=repo_name,
                    repo_path=repo_path,
                    file_path=file_path,
                    node=node,
                    pydantic_models=pydantic_models,
                    annotated_deps_map=annotated_deps_map,
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
            cors_config=self._extract_cors_config(tree),
        )
        return endpoints, module_facts

    # ──────────────────────────────────────────────────────────────────────────
    # Handler node collector (for service call tracer)
    # ──────────────────────────────────────────────────────────────────────────

    def _collect_handler_nodes(
        self,
        file_asts: dict[str, tuple[Path, ast.Module]],
        endpoints: list[BackendEndpoint],
    ) -> list[tuple[BackendEndpoint, ast.FunctionDef | ast.AsyncFunctionDef | None]]:
        """Pair each endpoint with its handler AST node for deep analysis."""
        func_index: dict[tuple[str, str], ast.FunctionDef | ast.AsyncFunctionDef] = {}
        for file_str, (file_path, tree) in file_asts.items():
            try:
                rel = str(file_path.relative_to(file_path.parents[len(file_path.parts) - 2]))
            except (ValueError, IndexError):
                rel = file_str
            for node in ast.walk(tree):
                if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    func_index[(file_str, node.name)] = node
                    func_index[(rel, node.name)] = node

        result: list[tuple[BackendEndpoint, ast.FunctionDef | ast.AsyncFunctionDef | None]] = []
        for ep in endpoints:
            handler = None
            if ep.function_name:
                for file_str in file_asts:
                    if file_str.endswith(ep.file) or ep.file in file_str:
                        handler = func_index.get((file_str, ep.function_name))
                        if handler:
                            break
                if handler is None:
                    handler = func_index.get((ep.file, ep.function_name))
            result.append((ep, handler))
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # Endpoint extraction helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _extract_endpoints_from_function(
        self,
        repo_name: str,
        repo_path: Path,
        file_path: Path,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        pydantic_models: dict[str, list[SchemaField]],
        annotated_deps_map: dict[str, list[str]],
        router_prefixes: dict[str, str],
        router_dependencies: dict[str, list[str]],
        app_names: set[str],
        app_dependencies: list[str],
    ) -> list[BackendEndpoint]:
        extracted: list[BackendEndpoint] = []

        request_schema, request_fields = self._extract_request_schema(node, pydantic_models)
        arg_dependencies = self._extract_dependencies_from_args(node, annotated_deps_map)
        call_refs = self._extract_call_refs(node)
        string_refs = self._extract_string_refs(node)
        wrapper_decorators = self._extract_non_route_decorators(node.decorator_list)
        has_try_except = self._contains_try_except(node)
        redacted_fields = self._detect_redacted_response_fields(node)
        returns_file_response = self._detect_file_response(node)

        for decorator in node.decorator_list:
            if not isinstance(decorator, ast.Call) or not isinstance(decorator.func, ast.Attribute):
                continue

            decorated_object = decorator.func.value
            if not isinstance(decorated_object, ast.Name):
                continue
            decorated_name = decorated_object.id

            is_websocket = decorator.func.attr in WEBSOCKET_DECORATORS
            method_candidates: list[str] = []
            if is_websocket:
                method_candidates = ["WS"]
            elif decorator.func.attr in HTTP_DECORATORS:
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
            # Look up response fields using the base model name (unwraps List[T], Optional[T], etc.)
            response_base = self._base_model_name(response_schema) if response_schema else None
            response_fields = pydantic_models.get(response_base, []) if response_base else []
            status_code_literal = self._extract_status_code_literal(decorator)

            decorator_dependencies = self._extract_dependencies_from_decorator(decorator)
            scoped_dependencies = list(arg_dependencies + decorator_dependencies)

            if decorated_name in router_dependencies:
                scoped_dependencies.extend(router_dependencies[decorated_name])
            if decorated_name in app_names:
                scoped_dependencies.extend(app_dependencies)

            try:
                rel_file = str(file_path.relative_to(repo_path))
            except ValueError:
                rel_file = str(file_path)
            line_number = getattr(decorator, "lineno", None) or getattr(node, "lineno", None)

            expects_body = request_schema is not None or self._has_body_param(node, pydantic_models)

            for method in method_candidates:
                extracted.append(
                    BackendEndpoint(
                        service=repo_name,
                        file=rel_file,
                        line=line_number,
                        path=full_path,
                        method=method,
                        is_websocket=is_websocket,
                        request_schema=request_schema,
                        request_fields=request_fields,
                        response_schema=response_schema,
                        response_fields=response_fields,
                        redacted_response_fields=redacted_fields,
                        dependencies=sorted(set(scoped_dependencies)),
                        function_name=node.name,
                        decorators=wrapper_decorators,
                        call_refs=call_refs,
                        string_refs=string_refs,
                        has_try_except=has_try_except,
                        expects_request_body=expects_body,
                        returns_file_response=returns_file_response,
                        status_code_literal=status_code_literal,
                    )
                )

        return extracted

    def _base_model_name(self, schema: str) -> str:
        """
        Extract the bare model class name from a potentially wrapped annotation.

        Examples:
        - ``UserResponse``         → ``UserResponse``
        - ``List[UserResponse]``   → ``UserResponse``
        - ``Optional[UserOut]``    → ``UserOut``
        - ``Page[Item]``           → ``Item``
        """
        m = _SUBSCRIPT_WRAPPER_RE.match(schema)
        if m:
            return m.group(1)
        # Handle T | None union syntax
        bare = schema.split("[")[0].split("|")[0].strip()
        return bare

    def _extract_request_schema(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        pydantic_models: dict[str, list[SchemaField]],
    ) -> tuple[str | None, list[SchemaField]]:
        """
        Find the request-body Pydantic model for a route handler.

        Only positional arguments WITHOUT a FastAPI non-body default (Depends,
        Query, Header, Cookie, Path, Security, File, Form) are considered.
        This prevents auth-dependency types such as ``RecruiterOut`` from being
        mistaken for the request body just because they share a base class with
        request DTOs.
        """
        # Build arg-name → default-value map (defaults are right-aligned in positional args)
        arg_default: dict[str, ast.expr] = {}
        n_pos = len(node.args.args)
        n_def = len(node.args.defaults)
        for offset, default in enumerate(node.args.defaults):
            idx = n_pos - n_def + offset
            if 0 <= idx < n_pos:
                arg_default[node.args.args[idx].arg] = default
        for kw_arg, kw_default in zip(node.args.kwonlyargs, node.args.kw_defaults):
            if kw_default is not None:
                arg_default[kw_arg.arg] = kw_default

        for arg in node.args.args + node.args.kwonlyargs:
            if arg.arg in _SKIP_ARG_NAMES:
                continue
            if arg.annotation is None:
                continue

            # Skip FastAPI non-body parameters (auth deps, query params, headers, etc.)
            default = arg_default.get(arg.arg)
            if default is not None and isinstance(default, ast.Call):
                short = self._resolve_name(default.func).split(".")[-1]
                if short in _FASTAPI_NON_BODY_DEFAULTS:
                    continue

            annotation = self._annotation_to_str(arg.annotation)
            base_name = self._base_model_name(annotation)
            if base_name in pydantic_models:
                return annotation, pydantic_models[base_name]
            # Fallback: if the annotation looks like a model type (starts with uppercase,
            # not a builtin), record it even without field details to avoid
            # missing_backend_schema false positives.
            if (
                base_name
                and base_name[0].isupper()
                and base_name not in {
                    "Request", "Response", "WebSocket",
                    "Dict", "List", "Set", "Tuple", "Optional", "Union",
                    "Any", "Callable", "Type", "Sequence",
                }
            ):
                return annotation, []
        return None, []

    def _extract_dependencies_from_args(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        annotated_deps_map: dict[str, list[str]] | None = None,
    ) -> list[str]:
        dependencies: list[str] = []
        annotated_deps_map = annotated_deps_map or {}

        # Style 1: old-style default-value Depends/Security  (user = Depends(get_current_user))
        _DEP_LIKE = ("Depends", "Security")
        defaults = list(node.args.defaults)
        arg_with_defaults = node.args.args[-len(defaults):] if defaults else []
        for arg, default in zip(arg_with_defaults, defaults, strict=False):
            if isinstance(default, ast.Call) and any(
                self._resolve_name(default.func).endswith(d) for d in _DEP_LIKE
            ):
                dep_name = self._resolve_name(default.args[0]) if default.args else "Depends"
                dependencies.append(f"{arg.arg}:{dep_name}")
        kw_defaults = node.args.kw_defaults
        for arg, default in zip(node.args.kwonlyargs, kw_defaults, strict=False):
            if isinstance(default, ast.Call) and any(
                self._resolve_name(default.func).endswith(d) for d in _DEP_LIKE
            ):
                dep_name = self._resolve_name(default.args[0]) if default.args else "Depends"
                dependencies.append(f"{arg.arg}:{dep_name}")

        # Style 2: Annotated-based Depends (modern FastAPI)
        # Handles both direct Annotated[T, Depends(func)] and type aliases
        already_extracted = {d.split(":")[0] for d in dependencies}
        for arg in node.args.args + node.args.kwonlyargs:
            if arg.arg in already_extracted:
                continue
            if arg.annotation is None:
                continue

            # Direct: user: Annotated[User, Depends(get_current_user)]
            direct_deps = self._extract_deps_from_annotated(arg.annotation)
            if direct_deps:
                for dep_name in direct_deps:
                    dependencies.append(f"{arg.arg}:{dep_name}")
                continue

            # Type alias: user: CurrentUserID  (where CurrentUserID = Annotated[str, Depends(...)])
            ann_name = self._resolve_name(arg.annotation)
            alias_name = ann_name.split(".")[-1] if ann_name else ""
            if alias_name in annotated_deps_map:
                for dep_name in annotated_deps_map[alias_name]:
                    dependencies.append(f"{arg.arg}:{dep_name}")

        return dependencies

    def _extract_dependencies_from_decorator(self, decorator: ast.Call) -> list[str]:
        return self._extract_dependencies_from_keyword(decorator.keywords, "dependencies")

    def _extract_dependencies_from_keyword(self, keywords: list[ast.keyword], key_name: str) -> list[str]:
        _DEP_LIKE = ("Depends", "Security")
        dependencies: list[str] = []
        for kw in keywords:
            if kw.arg != key_name:
                continue
            if not isinstance(kw.value, (ast.List, ast.Tuple)):
                continue
            for item in kw.value.elts:
                if not isinstance(item, ast.Call):
                    continue
                if not any(self._resolve_name(item.func).endswith(d) for d in _DEP_LIKE):
                    continue
                dep_name = self._resolve_name(item.args[0]) if item.args else "Depends"
                dependencies.append(dep_name)
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
                # Collect keyword argument names (e.g. user_id=..., owner_id=...)
                # so ownership markers match service calls like svc.get(user_id=x).
                for kw in item.keywords:
                    if kw.arg:
                        refs.add(kw.arg)
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

    def _detect_redacted_response_fields(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> list[str]:
        """
        Detect response-object fields that are cleared/redacted before return.

        Catches patterns like:
            result.access_token = ""
            result.field = None
            response.secret = ""
        """
        redacted: set[str] = set()
        for item in ast.walk(node):
            if not isinstance(item, ast.Assign):
                continue
            for target in item.targets:
                if not isinstance(target, ast.Attribute):
                    continue
                value = item.value
                is_clear = isinstance(value, ast.Constant) and value.value in ("", None)
                if is_clear:
                    redacted.add(target.attr)
        return sorted(redacted)

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

    def _extract_cors_config(self, tree: ast.Module) -> CorsConfig | None:
        """Extract CORS middleware configuration from add_middleware(CORSMiddleware, ...) calls."""
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            if not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr != "add_middleware":
                continue
            if not node.args:
                continue
            mw_name = self._resolve_name(node.args[0])
            if not mw_name or "cors" not in mw_name.lower():
                continue

            config = CorsConfig()
            for kw in node.keywords:
                if not kw.arg:
                    continue
                if kw.arg == "allow_origins":
                    config.allow_origins = self._extract_list_of_strings(kw.value)
                elif kw.arg == "allow_methods":
                    config.allow_methods = self._extract_list_of_strings(kw.value)
                elif kw.arg == "allow_headers":
                    config.allow_headers = self._extract_list_of_strings(kw.value)
                elif kw.arg == "allow_credentials":
                    if isinstance(kw.value, ast.Constant):
                        config.allow_credentials = bool(kw.value.value)

            config.is_permissive = (
                "*" in config.allow_origins and config.allow_credentials
            )
            return config
        return None

    def _extract_list_of_strings(self, node: ast.expr) -> list[str]:
        """Extract a list of string constants from an AST node."""
        if isinstance(node, ast.List):
            return [
                elt.value
                for elt in node.elts
                if isinstance(elt, ast.Constant) and isinstance(elt.value, str)
            ]
        if isinstance(node, ast.Constant) and isinstance(node.value, str):
            return [node.value]
        return []

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

    # ──────────────────────────────────────────────────────────────────────────
    # Endpoint-intent metadata detection
    # ──────────────────────────────────────────────────────────────────────────

    def _has_body_param(
        self,
        node: ast.FunctionDef | ast.AsyncFunctionDef,
        pydantic_models: dict[str, list],
    ) -> bool:
        """Check if the handler has any parameter that could be a request body.

        Returns True when at least one arg is NOT a known non-body kind and
        is NOT in the skip list, indicating it could receive body data.
        """
        arg_default: dict[str, ast.expr] = {}
        n_pos = len(node.args.args)
        n_def = len(node.args.defaults)
        for offset, default in enumerate(node.args.defaults):
            idx = n_pos - n_def + offset
            if 0 <= idx < n_pos:
                arg_default[node.args.args[idx].arg] = default
        for kw_arg, kw_default in zip(node.args.kwonlyargs, node.args.kw_defaults):
            if kw_default is not None:
                arg_default[kw_arg.arg] = kw_default

        for arg in node.args.args + node.args.kwonlyargs:
            if arg.arg in _SKIP_ARG_NAMES:
                continue
            if arg.annotation is None:
                continue
            default = arg_default.get(arg.arg)
            if default is not None and isinstance(default, ast.Call):
                short = self._resolve_name(default.func).split(".")[-1]
                if short in _FASTAPI_NON_BODY_DEFAULTS:
                    continue
            ann = self._annotation_to_str(arg.annotation)
            base = self._base_model_name(ann)
            if base in pydantic_models:
                return True
        return False

    def _detect_file_response(self, node: ast.FunctionDef | ast.AsyncFunctionDef) -> bool:
        """Detect if handler returns a file/stream response (AST-based)."""
        _FILE_RESPONSE_TYPES = {
            "FileResponse", "StreamingResponse", "Response",
        }
        # Check return annotation
        if node.returns:
            ann = self._annotation_to_str(node.returns)
            base = ann.split(".")[-1]
            if base in _FILE_RESPONSE_TYPES:
                return True

        for child in ast.walk(node):
            if not isinstance(child, ast.Return) or child.value is None:
                continue
            ret = child.value
            if isinstance(ret, ast.Call):
                callee = self._resolve_name(ret.func).split(".")[-1]
                if callee in _FILE_RESPONSE_TYPES:
                    return True
        return False

    def _extract_status_code_literal(self, decorator: ast.Call) -> int | None:
        """Extract status_code from route decorator (e.g. @router.post(..., status_code=204))."""
        for kw in decorator.keywords:
            if kw.arg != "status_code":
                continue
            if isinstance(kw.value, ast.Constant) and isinstance(kw.value.value, int):
                return kw.value.value
            if isinstance(kw.value, ast.Attribute):
                attr = kw.value.attr.upper()
                # Parse numeric suffix from names like HTTP_204_NO_CONTENT
                parts = attr.split("_")
                for part in parts:
                    if part.isdigit():
                        return int(part)
        return None

    # ──────────────────────────────────────────────────────────────────────────
    # AST utility methods
    # ──────────────────────────────────────────────────────────────────────────

    def _inherits_from_base_model(self, class_def: ast.ClassDef) -> bool:
        for base in class_def.bases:
            base_name = self._resolve_name(base)
            if base_name.endswith("BaseModel"):
                return True
        return False

    _ORM_COLUMN_CALL_NAMES: frozenset[str] = frozenset({
        "Column", "mapped_column", "column_property",
        "CharField", "IntField", "TextField", "BooleanField",
        "FloatField", "DecimalField", "DatetimeField", "DateField",
        "ForeignKeyField", "ManyToManyField", "OneToOneField",
        "JSONField", "BinaryField", "UUIDField", "BigIntField",
        "SmallIntField", "IntegerField", "BoolField",
    })

    def _is_orm_model_class(self, class_def: ast.ClassDef) -> bool:
        for base in class_def.bases:
            name = self._resolve_name(base)
            if name.endswith("BaseModel") or name.endswith("BaseSettings"):
                return False

        has_tablename = self._class_has_tablename(class_def)
        has_orm_cols = self._has_orm_column_definitions(class_def)

        for base in class_def.bases:
            name = self._resolve_name(base)
            short = name.split(".")[-1]

            if short in {"DeclarativeBase", "MappedAsDataclass"}:
                return True
            if short == "Base" and (has_tablename or has_orm_cols):
                return True
            if name == "db.Model":
                return True
            if short == "Model" and (has_tablename or has_orm_cols):
                return True

        return False

    def _class_has_tablename(self, class_def: ast.ClassDef) -> bool:
        for child in class_def.body:
            if not isinstance(child, ast.Assign):
                continue
            for target in child.targets:
                if isinstance(target, ast.Name) and target.id == "__tablename__":
                    return True
        return False

    def _has_orm_column_definitions(self, class_def: ast.ClassDef) -> bool:
        for child in class_def.body:
            if isinstance(child, ast.Assign) and isinstance(child.value, ast.Call):
                call_name = self._resolve_name(child.value.func).split(".")[-1]
                if call_name in self._ORM_COLUMN_CALL_NAMES:
                    return True
            if isinstance(child, ast.AnnAssign) and child.value is not None:
                if isinstance(child.value, ast.Call):
                    call_name = self._resolve_name(child.value.func).split(".")[-1]
                    if call_name in self._ORM_COLUMN_CALL_NAMES:
                        return True
                if child.annotation:
                    ann = self._annotation_to_str(child.annotation)
                    if "Mapped" in ann:
                        return True
        return False

    def _extract_orm_columns(self, class_def: ast.ClassDef) -> list[str]:
        columns: list[str] = []
        for child in class_def.body:
            if isinstance(child, ast.Assign):
                for target in child.targets:
                    if not isinstance(target, ast.Name) or target.id.startswith("_"):
                        continue
                    if isinstance(child.value, ast.Call):
                        call_name = self._resolve_name(child.value.func).split(".")[-1]
                        if call_name in self._ORM_COLUMN_CALL_NAMES:
                            columns.append(target.id)
            elif isinstance(child, ast.AnnAssign) and isinstance(child.target, ast.Name):
                name = child.target.id
                if name.startswith("_"):
                    continue
                if child.value is not None and isinstance(child.value, ast.Call):
                    call_name = self._resolve_name(child.value.func).split(".")[-1]
                    if call_name in self._ORM_COLUMN_CALL_NAMES:
                        columns.append(name)
                        continue
                if child.annotation:
                    ann = self._annotation_to_str(child.annotation)
                    if "Mapped" in ann:
                        columns.append(name)
        return columns

    def _build_global_orm_models(
        self,
        file_asts: dict[str, tuple[Path, ast.Module]],
    ) -> dict[str, list[str]]:
        """Build a repo-wide name -> column-names map for every ORM model class."""
        models: dict[str, list[str]] = {}
        for _file_str, (_, tree) in file_asts.items():
            for node in tree.body:
                if not isinstance(node, ast.ClassDef):
                    continue
                if not self._is_orm_model_class(node):
                    continue
                models[node.name] = self._extract_orm_columns(node)
        return models

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

    @staticmethod
    def _is_non_config_url(url: str) -> bool:
        lowered = url.lower()
        return any(host in lowered for host in _NON_CONFIG_URL_HOSTS)

    def _collect_base_settings_urls(self, tree: ast.Module, content: str) -> set[str]:
        """Collect URL strings found inside Pydantic BaseSettings class bodies."""
        urls: set[str] = set()
        lines = content.splitlines(keepends=True)
        for node in ast.walk(tree):
            if not isinstance(node, ast.ClassDef):
                continue
            if not any(
                self._resolve_name(base).endswith("BaseSettings")
                for base in node.bases
            ):
                continue
            start = node.lineno - 1
            end = node.end_lineno if hasattr(node, "end_lineno") and node.end_lineno else start + 1
            class_text = "".join(lines[start:end])
            urls.update(URL_PATTERN.findall(class_text))
        return urls

    def _iter_py_files(self, repo_path: Path) -> list[Path]:
        files: list[Path] = []
        for path in repo_path.rglob("*.py"):
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            files.append(path)
        return files
