"""AST-based semantic code index for accurate evidence marker matching.

Replaces text-based substring scanning with Python AST analysis so that
markers like ``authorize`` do not false-positive on ``authorization``
parameter names or ``HTTP_401_UNAUTHORIZED`` constants.
"""

from __future__ import annotations

import ast
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

_IGNORED_DIRS = frozenset({
    ".git", "node_modules", "dist", "build",
    ".venv", "venv", "__pycache__", ".pytest_cache",
})


@dataclass
class ASTHit:
    """A single semantic hit from AST analysis."""
    file: str
    line: int
    node_type: str
    name: str
    module_origin: str
    excerpt: str
    marker: str = ""


def _resolve_call_name(node: ast.expr) -> str | None:
    """Extract the function/method name from a Call node's func."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return node.attr
    return None


def _resolve_full_call(node: ast.expr) -> str:
    """Produce dotted call path like ``obj.method``."""
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        parent = _resolve_full_call(node.value)
        return f"{parent}.{node.attr}" if parent else node.attr
    return ""


def _get_source_line(lines: list[str], lineno: int) -> str:
    if 0 < lineno <= len(lines):
        return lines[lineno - 1].strip()[:180]
    return ""


class ASTCodeIndex:
    """Semantic code index built from parsed Python ASTs.

    Walks every AST once and classifies nodes into semantic buckets
    (imports, calls, base-classes, decorators, definitions, keyword-args,
    string-literals) so downstream queries can match precisely.
    """

    def __init__(self) -> None:
        self._imports: dict[str, list[ASTHit]] = {}
        self._calls: dict[str, list[ASTHit]] = {}
        self._class_bases: dict[str, list[ASTHit]] = {}
        self._decorators: dict[str, list[ASTHit]] = {}
        self._definitions: dict[str, list[ASTHit]] = {}
        self._keyword_args: dict[str, list[ASTHit]] = {}
        self._string_literals: dict[str, list[ASTHit]] = {}
        self._source_lines: dict[str, dict[str, list[str]]] = {}

    # ------------------------------------------------------------------
    # Construction
    # ------------------------------------------------------------------

    @classmethod
    def build_multi(
        cls,
        repo_file_asts: dict[str, dict[str, tuple[Path, ast.Module]]],
        repo_paths: dict[str, str],
    ) -> "ASTCodeIndex":
        """Build an index spanning multiple services from pre-parsed ASTs."""
        idx = cls()
        for service, file_asts in repo_file_asts.items():
            root_raw = repo_paths.get(service)
            repo_root = Path(root_raw) if root_raw else None
            idx._index_service(service, file_asts, repo_root)
        return idx

    @classmethod
    def build_from_paths(cls, repo_paths: dict[str, str]) -> "ASTCodeIndex":
        """Fallback: parse files from disk when no pre-parsed ASTs available."""
        idx = cls()
        for service, root_raw in repo_paths.items():
            root = Path(root_raw)
            if not root.exists():
                continue
            file_asts: dict[str, tuple[Path, ast.Module]] = {}
            for fpath in root.rglob("*.py"):
                if any(part in _IGNORED_DIRS for part in fpath.parts):
                    continue
                if not fpath.is_file():
                    continue
                try:
                    content = fpath.read_text(encoding="utf-8", errors="ignore")
                    tree = ast.parse(content)
                    file_asts[str(fpath)] = (fpath, tree)
                except (SyntaxError, UnicodeDecodeError, OSError):
                    continue
            idx._index_service(service, file_asts, root)
        return idx

    def _index_service(
        self,
        service: str,
        file_asts: dict[str, tuple[Path, ast.Module]],
        repo_root: Path | None,
    ) -> None:
        imports: list[ASTHit] = []
        calls: list[ASTHit] = []
        class_bases: list[ASTHit] = []
        decorators: list[ASTHit] = []
        definitions: list[ASTHit] = []
        keyword_args: list[ASTHit] = []
        string_literals: list[ASTHit] = []
        source_lines: dict[str, list[str]] = {}

        import_map: dict[str, str] = {}

        for _file_key, (fpath, tree) in file_asts.items():
            try:
                rel = str(fpath.relative_to(repo_root)) if repo_root else str(fpath)
            except ValueError:
                rel = str(fpath)

            try:
                lines = fpath.read_text(encoding="utf-8", errors="ignore").splitlines()
            except OSError:
                lines = []
            source_lines[rel] = lines

            file_import_map: dict[str, str] = {}

            for node in ast.walk(tree):
                if isinstance(node, ast.ImportFrom) and node.module:
                    for alias in node.names:
                        local_name = alias.asname or alias.name
                        full_module = node.module
                        file_import_map[local_name] = full_module
                        imports.append(ASTHit(
                            file=rel,
                            line=node.lineno,
                            node_type="import",
                            name=alias.name,
                            module_origin=full_module,
                            excerpt=_get_source_line(lines, node.lineno),
                        ))

                elif isinstance(node, ast.Import):
                    for alias in node.names:
                        local_name = alias.asname or alias.name
                        file_import_map[local_name] = alias.name
                        imports.append(ASTHit(
                            file=rel,
                            line=node.lineno,
                            node_type="import",
                            name=alias.name,
                            module_origin=alias.name,
                            excerpt=_get_source_line(lines, node.lineno),
                        ))

                elif isinstance(node, ast.Call):
                    func_name = _resolve_call_name(node.func)
                    if func_name:
                        full_call = _resolve_full_call(node.func)
                        origin = file_import_map.get(
                            full_call.split(".")[0], ""
                        ) if "." in full_call else file_import_map.get(func_name, "")
                        calls.append(ASTHit(
                            file=rel,
                            line=getattr(node, "lineno", 0),
                            node_type="call",
                            name=func_name,
                            module_origin=origin,
                            excerpt=_get_source_line(lines, getattr(node, "lineno", 0)),
                        ))

                    for kw in node.keywords:
                        if kw.arg:
                            parent_call = _resolve_call_name(node.func) or ""
                            keyword_args.append(ASTHit(
                                file=rel,
                                line=getattr(node, "lineno", 0),
                                node_type="keyword_arg",
                                name=kw.arg,
                                module_origin=parent_call,
                                excerpt=_get_source_line(lines, getattr(node, "lineno", 0)),
                            ))

                elif isinstance(node, ast.ClassDef):
                    definitions.append(ASTHit(
                        file=rel,
                        line=node.lineno,
                        node_type="class_def",
                        name=node.name,
                        module_origin="",
                        excerpt=_get_source_line(lines, node.lineno),
                    ))
                    for base in node.bases:
                        base_name: str | None = None
                        if isinstance(base, ast.Name):
                            base_name = base.id
                        elif isinstance(base, ast.Attribute):
                            base_name = base.attr
                        if base_name:
                            class_bases.append(ASTHit(
                                file=rel,
                                line=node.lineno,
                                node_type="base_class",
                                name=base_name,
                                module_origin=file_import_map.get(base_name, ""),
                                excerpt=_get_source_line(lines, node.lineno),
                            ))

                    for deco in node.decorator_list:
                        deco_name = _resolve_call_name(deco) if isinstance(deco, ast.Call) else (
                            deco.id if isinstance(deco, ast.Name) else (
                                deco.attr if isinstance(deco, ast.Attribute) else None
                            )
                        )
                        if deco_name:
                            decorators.append(ASTHit(
                                file=rel,
                                line=getattr(deco, "lineno", node.lineno),
                                node_type="decorator",
                                name=deco_name,
                                module_origin="",
                                excerpt=_get_source_line(lines, getattr(deco, "lineno", node.lineno)),
                            ))

                elif isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                    definitions.append(ASTHit(
                        file=rel,
                        line=node.lineno,
                        node_type="func_def",
                        name=node.name,
                        module_origin="",
                        excerpt=_get_source_line(lines, node.lineno),
                    ))
                    for deco in node.decorator_list:
                        deco_name = _resolve_call_name(deco) if isinstance(deco, ast.Call) else (
                            deco.id if isinstance(deco, ast.Name) else (
                                deco.attr if isinstance(deco, ast.Attribute) else None
                            )
                        )
                        if deco_name:
                            decorators.append(ASTHit(
                                file=rel,
                                line=getattr(deco, "lineno", node.lineno),
                                node_type="decorator",
                                name=deco_name,
                                module_origin="",
                                excerpt=_get_source_line(lines, getattr(deco, "lineno", node.lineno)),
                            ))

                elif isinstance(node, ast.Constant) and isinstance(node.value, str):
                    string_literals.append(ASTHit(
                        file=rel,
                        line=getattr(node, "lineno", 0),
                        node_type="string_literal",
                        name=node.value[:200],
                        module_origin="",
                        excerpt=_get_source_line(lines, getattr(node, "lineno", 0)),
                    ))

            import_map.update(file_import_map)

        self._imports[service] = imports
        self._calls[service] = calls
        self._class_bases[service] = class_bases
        self._decorators[service] = decorators
        self._definitions[service] = definitions
        self._keyword_args[service] = keyword_args
        self._string_literals[service] = string_literals
        self._source_lines[service] = source_lines

    # ------------------------------------------------------------------
    # Query methods
    # ------------------------------------------------------------------

    def find_imports(
        self,
        service: str,
        name: str,
        *,
        from_module: str | None = None,
        file_hint: str | None = None,
    ) -> list[ASTHit]:
        hits = []
        for h in self._imports.get(service, []):
            if h.name.lower() != name.lower():
                continue
            if from_module:
                if not _module_matches(h.module_origin, from_module):
                    continue
            if file_hint and not _matches_file_hint(h.file, file_hint):
                continue
            hits.append(h)
        return hits

    def find_calls(
        self,
        service: str,
        name: str,
        *,
        exclude_modules: list[str] | None = None,
        file_hint: str | None = None,
    ) -> list[ASTHit]:
        hits = []
        name_low = name.lower()
        for h in self._calls.get(service, []):
            if h.name.lower() != name_low:
                continue
            if exclude_modules and any(
                _module_matches(h.module_origin, ex) for ex in exclude_modules
            ):
                continue
            if file_hint and not _matches_file_hint(h.file, file_hint):
                continue
            hits.append(h)
        return hits

    def find_base_classes(
        self,
        service: str,
        name: str,
        *,
        exclude_parents: list[str] | None = None,
        file_hint: str | None = None,
    ) -> list[ASTHit]:
        hits = []
        name_low = name.lower()
        exclude_set = frozenset(e.lower() for e in (exclude_parents or []))
        for h in self._class_bases.get(service, []):
            if h.name.lower() != name_low:
                continue
            if h.name.lower() in exclude_set:
                continue
            if file_hint and not _matches_file_hint(h.file, file_hint):
                continue
            hits.append(h)
        return hits

    def find_decorators(
        self,
        service: str,
        name: str,
        *,
        file_hint: str | None = None,
    ) -> list[ASTHit]:
        hits = []
        name_low = name.lower()
        for h in self._decorators.get(service, []):
            if h.name.lower() != name_low:
                continue
            if file_hint and not _matches_file_hint(h.file, file_hint):
                continue
            hits.append(h)
        return hits

    def find_definitions(
        self,
        service: str,
        name: str,
        *,
        def_type: str | None = None,
        file_hint: str | None = None,
    ) -> list[ASTHit]:
        hits = []
        name_low = name.lower()
        for h in self._definitions.get(service, []):
            if h.name.lower() != name_low:
                continue
            if def_type and h.node_type != def_type:
                continue
            if file_hint and not _matches_file_hint(h.file, file_hint):
                continue
            hits.append(h)
        return hits

    def find_keyword_args(
        self,
        service: str,
        name: str,
        *,
        in_call: str | None = None,
        file_hint: str | None = None,
    ) -> list[ASTHit]:
        hits = []
        name_low = name.lower()
        for h in self._keyword_args.get(service, []):
            if h.name.lower() != name_low:
                continue
            if in_call and h.module_origin.lower() != in_call.lower():
                continue
            if file_hint and not _matches_file_hint(h.file, file_hint):
                continue
            hits.append(h)
        return hits

    def find_string_literals(
        self,
        service: str,
        pattern: str,
        *,
        file_hint: str | None = None,
    ) -> list[ASTHit]:
        try:
            compiled = re.compile(pattern, re.IGNORECASE)
        except re.error:
            return []
        hits = []
        for h in self._string_literals.get(service, []):
            if not compiled.search(h.name):
                continue
            if file_hint and not _matches_file_hint(h.file, file_hint):
                continue
            hits.append(h)
        return hits

    def find_text_with_boundary(
        self,
        service: str,
        pattern: str,
        *,
        file_hint: str | None = None,
    ) -> list[ASTHit]:
        """Fallback: word-boundary regex on raw source lines."""
        try:
            compiled = re.compile(rf"\b{re.escape(pattern)}\b", re.IGNORECASE)
        except re.error:
            return []
        hits = []
        for rel_path, lines in self._source_lines.get(service, {}).items():
            if file_hint and not _matches_file_hint(rel_path, file_hint):
                continue
            for idx, line in enumerate(lines, start=1):
                if compiled.search(line):
                    hits.append(ASTHit(
                        file=rel_path,
                        line=idx,
                        node_type="text",
                        name=pattern,
                        module_origin="",
                        excerpt=line.strip()[:180],
                    ))
        return hits


# ------------------------------------------------------------------
# Marker resolution: dispatch structured markers to AST queries
# ------------------------------------------------------------------

def resolve_marker_hits(
    ast_index: ASTCodeIndex,
    service: str,
    markers: list[Any],
    *,
    file_hint: str | None = None,
) -> list[ASTHit]:
    """Dispatch each structured marker to the appropriate AST query.

    Markers can be plain strings (legacy fallback with word-boundary regex)
    or dicts with a ``type`` key specifying the AST query kind.
    """
    hits: list[ASTHit] = []
    for marker in markers:
        if not marker:
            continue
        if isinstance(marker, str):
            new_hits = ast_index.find_text_with_boundary(service, marker, file_hint=file_hint)
            for h in new_hits:
                h.marker = marker
            hits.extend(new_hits)
        elif isinstance(marker, dict):
            mtype = marker.get("type", "text")
            mname = marker.get("name", "")
            new_hits: list[ASTHit] = []

            if mtype == "call":
                new_hits = ast_index.find_calls(
                    service, mname,
                    exclude_modules=marker.get("exclude_modules"),
                    file_hint=file_hint,
                )
            elif mtype == "import":
                new_hits = ast_index.find_imports(
                    service, mname,
                    from_module=marker.get("from_module"),
                    file_hint=file_hint,
                )
            elif mtype == "base_class":
                new_hits = ast_index.find_base_classes(
                    service, mname,
                    exclude_parents=marker.get("exclude"),
                    file_hint=file_hint,
                )
            elif mtype == "decorator":
                new_hits = ast_index.find_decorators(
                    service, mname,
                    file_hint=file_hint,
                )
            elif mtype == "keyword_arg":
                new_hits = ast_index.find_keyword_args(
                    service, mname,
                    in_call=marker.get("in_call"),
                    file_hint=file_hint,
                )
            elif mtype == "string_literal":
                pattern = marker.get("pattern", mname)
                new_hits = ast_index.find_string_literals(
                    service, pattern,
                    file_hint=file_hint,
                )
            elif mtype == "definition":
                new_hits = ast_index.find_definitions(
                    service, mname,
                    def_type=marker.get("def_type"),
                    file_hint=file_hint,
                )
            else:
                new_hits = ast_index.find_text_with_boundary(
                    service, marker.get("pattern", mname),
                    file_hint=file_hint,
                )

            marker_label = mname or marker.get("pattern", str(marker))
            for h in new_hits:
                h.marker = marker_label
            hits.extend(new_hits)
    return hits


# ------------------------------------------------------------------
# Helpers
# ------------------------------------------------------------------

def _module_matches(origin: str, pattern: str) -> bool:
    """Check if ``origin`` module matches ``pattern``.

    Supports ``|``-separated alternatives and prefix matching.
    """
    if not origin or not pattern:
        return False
    origin_low = origin.lower()
    for alt in pattern.split("|"):
        alt = alt.strip().lower()
        if not alt:
            continue
        if origin_low == alt or origin_low.startswith(alt + ".") or origin_low.startswith(alt):
            return True
    return False


def _matches_file_hint(rel_file: str, file_hint: str | None) -> bool:
    if not file_hint:
        return True
    return rel_file.endswith(file_hint) or file_hint.endswith(rel_file)
