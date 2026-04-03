from __future__ import annotations

import json
import re
from pathlib import Path

from src.observability.logging.setup import get_logger
from src.schemas.internal import FrontendCall, StaticAnalysisResult

logger = get_logger(__name__)

IGNORED_DIRS = {".git", "node_modules", "dist", "build", ".next", "coverage", ".turbo"}
SUPPORTED_SUFFIXES = {".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs"}
ENV_PATTERN = re.compile(r"(?:process\.env|import\.meta\.env)\.([A-Z0-9_]+)")
URL_PATTERN = re.compile(r"https?://[^'\"\s)]+")

_BARE_IDENTIFIER_RE = re.compile(r"^[a-zA-Z_$]\w*$")

_NON_CONFIG_URL_HOSTS: frozenset[str] = frozenset({
    "w3.org", "schema.org", "json-schema.org", "purl.org",
    "openid.net", "xml.org", "xmlsoap.org", "xmlns.com",
    "relaxng.org", "mozilla.org/MPL", "creativecommons.org",
    "spdx.org", "semver.org",
})

# Objects that are definitively not HTTP API clients.
# Prevents false positives from DOM, console, native JS, and common UI objects.
_NON_API_OBJECTS: frozenset[str] = frozenset({
    "console", "window", "document", "process", "Object", "Array", "String",
    "Math", "JSON", "Promise", "Error", "Date", "RegExp", "Set", "Map",
    "parseInt", "parseFloat", "isNaN", "isFinite",
    "localStorage", "sessionStorage", "navigator", "location", "history",
    "performance", "crypto", "URL", "URLSearchParams",
    "React", "ReactDOM", "router", "Router", "useRouter",
    "fs", "path", "os", "util", "stream", "http", "https",
    # already handled by dedicated extractors
    "axios", "fetch",
})

# HTTP verb method names used for custom client detection
_HTTP_VERB_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})

# Detect `someObject.get(url, ...)` / `someObject.post(url, data, ...)` patterns
# where someObject is not in _NON_API_OBJECTS.
_CUSTOM_METHOD_PATTERN = re.compile(r"\b(\w+)\.(get|post|put|patch|delete|head|options)\s*\(")


class ReactParser:
    def __init__(self) -> None:
        self._has_tree_sitter = False
        try:
            # Preferred parser path when installed.
            from tree_sitter_languages import get_parser  # noqa: F401

            self._has_tree_sitter = True
        except Exception:
            self._has_tree_sitter = False

    def parse(self, repo_name: str, repo_path: Path) -> StaticAnalysisResult:
        frontend_calls: list[FrontendCall] = []
        env_references: set[str] = set()
        hardcoded_urls: set[str] = set()
        parser_errors: list[str] = []

        for file_path in self._iter_source_files(repo_path):
            try:
                content = file_path.read_text(encoding="utf-8", errors="ignore")
            except OSError as exc:
                parser_errors.append(f"{file_path}: {exc}")
                continue

            env_references.update(ENV_PATTERN.findall(content))
            hardcoded_urls.update(URL_PATTERN.findall(content))

            try:
                rel_file = str(file_path.relative_to(repo_path))
                raw_calls: list[FrontendCall] = []
                raw_calls.extend(self._extract_fetch_calls(repo_name, rel_file, content))
                raw_calls.extend(self._extract_axios_method_calls(repo_name, rel_file, content))
                raw_calls.extend(self._extract_axios_object_calls(repo_name, rel_file, content))
                raw_calls.extend(self._extract_custom_http_calls(repo_name, rel_file, content))
                # Deduplicate by (file, line, method, raw_url) – custom extractor can
                # overlap with axios extractor on files that also import axios directly.
                seen: set[tuple[str, int | None, str, str]] = set()
                for call in raw_calls:
                    key = (call.file, call.line, call.method, call.raw_url)
                    if key not in seen:
                        seen.add(key)
                        frontend_calls.append(call)
            except Exception as exc:  # noqa: BLE001
                logger.exception("react_parser_failed file=%s", file_path, extra={"request_id": "-"})
                parser_errors.append(f"{file_path}: parser failure {exc}")

        filtered_urls = {
            url for url in hardcoded_urls
            if not self._is_non_config_url(url)
        }

        return StaticAnalysisResult(
            repo=repo_name,
            frontend_calls=frontend_calls,
            env_references=sorted(env_references),
            hardcoded_urls=sorted(filtered_urls),
            parser_errors=parser_errors,
        )

    def _extract_fetch_calls(self, service: str, file: str, content: str) -> list[FrontendCall]:
        calls: list[FrontendCall] = []
        for start in self._find_token_occurrences(content, "fetch("):
            args = self._extract_balanced_arguments(content, start + len("fetch"))
            if args is None:
                continue
            parts = self._split_top_level(args, ",", maxsplit=1)
            url_expr = parts[0].strip() if parts else ""
            options_expr = parts[1].strip() if len(parts) > 1 else ""

            method = self._find_option_value(options_expr, "method") or "GET"
            body_expr = self._find_option_expression(options_expr, "body")
            headers_expr = self._find_option_expression(options_expr, "headers")

            payload_fields = self._extract_payload_fields(body_expr)
            headers = self._extract_object_as_string_map(headers_expr)
            env_vars = sorted(set(ENV_PATTERN.findall(url_expr + "\n" + options_expr)))

            raw_url = self._strip_wrapping_quotes(url_expr)
            calls.append(
                FrontendCall(
                    service=service,
                    file=file,
                    line=self._line_of_index(content, start),
                    raw_url=raw_url,
                    method=method.upper(),
                    payload_fields=payload_fields,
                    payload_unresolved=self._is_unresolved_payload(body_expr, payload_fields),
                    url_unresolved=self._is_bare_identifier(url_expr),
                    headers=headers,
                    env_vars=env_vars,
                )
            )
        return calls

    def _extract_axios_method_calls(self, service: str, file: str, content: str) -> list[FrontendCall]:
        calls: list[FrontendCall] = []
        pattern = re.compile(r"axios\.(get|post|put|patch|delete|options|head)\s*\(")
        for match in pattern.finditer(content):
            method = match.group(1).upper()
            args = self._extract_balanced_arguments(content, match.end() - 1)
            if args is None:
                continue
            parts = self._split_top_level(args, ",", maxsplit=2)
            url_expr = parts[0].strip() if parts else ""
            payload_expr = parts[1].strip() if len(parts) > 1 and method in {"POST", "PUT", "PATCH"} else ""
            config_expr = parts[2].strip() if len(parts) > 2 else (parts[1].strip() if len(parts) > 1 else "")

            headers_expr = self._find_option_expression(config_expr, "headers")
            headers = self._extract_object_as_string_map(headers_expr)
            payload_fields = self._extract_payload_fields(payload_expr)

            calls.append(
                FrontendCall(
                    service=service,
                    file=file,
                    line=self._line_of_index(content, match.start()),
                    raw_url=self._strip_wrapping_quotes(url_expr),
                    method=method,
                    payload_fields=payload_fields,
                    payload_unresolved=self._is_unresolved_payload(payload_expr, payload_fields),
                    url_unresolved=self._is_bare_identifier(url_expr),
                    headers=headers,
                    env_vars=sorted(set(ENV_PATTERN.findall(url_expr + "\n" + config_expr))),
                )
            )
        return calls

    def _extract_axios_object_calls(self, service: str, file: str, content: str) -> list[FrontendCall]:
        calls: list[FrontendCall] = []
        pattern = re.compile(r"(?<!\.)axios\s*\(")
        for match in pattern.finditer(content):
            args = self._extract_balanced_arguments(content, match.end() - 1)
            if args is None:
                continue
            object_expr = args.strip()
            method = self._find_option_value(object_expr, "method") or "GET"
            url_expr = self._find_option_expression(object_expr, "url") or ""
            data_expr = self._find_option_expression(object_expr, "data")
            headers_expr = self._find_option_expression(object_expr, "headers")
            payload_fields = self._extract_payload_fields(data_expr)

            calls.append(
                FrontendCall(
                    service=service,
                    file=file,
                    line=self._line_of_index(content, match.start()),
                    raw_url=self._strip_wrapping_quotes(url_expr),
                    method=method.upper(),
                    payload_fields=payload_fields,
                    payload_unresolved=self._is_unresolved_payload(data_expr, payload_fields),
                    url_unresolved=self._is_bare_identifier(url_expr),
                    headers=self._extract_object_as_string_map(headers_expr),
                    env_vars=sorted(set(ENV_PATTERN.findall(object_expr))),
                )
            )
        return calls

    def _extract_custom_http_calls(self, service: str, file: str, content: str) -> list[FrontendCall]:
        """
        Detect HTTP API calls made through custom client/service objects.

        Covers patterns such as::

            apiClient.get('/users')
            httpService.post('/users', { name })
            myApi.put(`/users/${id}`, payload)
            request({ method: 'POST', url: '/endpoint' })

        Objects in ``_NON_API_OBJECTS`` (DOM, console, stdlib, etc.) are skipped.
        The first argument is validated to look like an API URL (starts with ``/``,
        ``http://``, ``https://``, contains an env-var reference, or is a template
        literal with a path-like string) to avoid false positives from unrelated
        method calls.
        """
        calls: list[FrontendCall] = []

        for match in _CUSTOM_METHOD_PATTERN.finditer(content):
            obj_name = match.group(1)
            method = match.group(2).upper()

            # Skip non-API objects and single-character / purely upper-case names
            # (likely a class constructor call like MyClass.get).
            if obj_name.lower() in {n.lower() for n in _NON_API_OBJECTS}:
                continue
            if obj_name[0].isupper() or len(obj_name) <= 1:
                continue

            # Extract the argument list
            args = self._extract_balanced_arguments(content, match.end() - 1)
            if args is None:
                continue

            parts = self._split_top_level(args, ",", maxsplit=2)
            url_expr = parts[0].strip() if parts else ""
            if not url_expr:
                continue

            # Only proceed if the first argument looks like an API URL
            if not self._looks_like_api_url(url_expr):
                continue

            raw_url = self._strip_wrapping_quotes(url_expr)
            # For PUT/POST/PATCH the second arg is typically the payload
            payload_expr = parts[1].strip() if len(parts) > 1 and method in {"POST", "PUT", "PATCH"} else ""
            config_expr = parts[2].strip() if len(parts) > 2 else (parts[1].strip() if len(parts) > 1 else "")
            headers_expr = self._find_option_expression(config_expr, "headers")

            env_vars = sorted(set(ENV_PATTERN.findall(url_expr + "\n" + config_expr)))
            payload_fields = self._extract_payload_fields(payload_expr)

            calls.append(
                FrontendCall(
                    service=service,
                    file=file,
                    line=self._line_of_index(content, match.start()),
                    raw_url=raw_url,
                    method=method,
                    payload_fields=payload_fields,
                    payload_unresolved=self._is_unresolved_payload(payload_expr, payload_fields),
                    url_unresolved=self._is_bare_identifier(url_expr),
                    headers=self._extract_object_as_string_map(headers_expr),
                    env_vars=env_vars,
                )
            )

        return calls

    def _looks_like_api_url(self, url_expr: str) -> bool:
        """
        Return True when an expression is very likely to be an HTTP API URL.

        Accepts:
        - String literals starting with ``/`` (relative path)
        - String literals starting with ``http://`` / ``https://``
        - Template literals containing ``/`` segments or env-var references
        - Expressions referencing ``import.meta.env`` / ``process.env``
        - Concatenations that include a ``/`` path fragment
        """
        stripped = self._strip_wrapping_quotes(url_expr.strip())
        if stripped.startswith("/"):
            return True
        if stripped.startswith(("http://", "https://")):
            return True
        # Template literal: `${API_BASE}/users` or `/users/${id}`
        if "`" in url_expr and ("${" in url_expr or re.search(r"/\w", url_expr)):
            return True
        # Env-var concatenation: import.meta.env.VITE_API_URL + "/users"
        if "import.meta.env" in url_expr or "process.env" in url_expr:
            return True
        # String concatenation where one part is a path string: baseUrl + "/users"
        if re.search(r'["\'][/\w][^"\']*["\']', url_expr):
            candidate = re.search(r'["\']([^"\']+)["\']', url_expr)
            if candidate and candidate.group(1).startswith("/"):
                return True
        return False

    def _extract_payload_fields(self, body_expr: str) -> dict[str, str]:
        if not body_expr:
            return {}

        expression = body_expr.strip()
        stringify_match = re.search(r"JSON\.stringify\s*\((\{[\s\S]*\})\)", expression)
        if stringify_match:
            expression = stringify_match.group(1)

        return self._extract_object_field_types(expression)

    def _extract_object_field_types(self, expr: str) -> dict[str, str]:
        object_text = self._extract_outer_object(expr)
        if not object_text:
            return {}

        body = object_text[1:-1]
        chunks = self._split_top_level(body, ",")
        fields: dict[str, str] = {}
        for chunk in chunks:
            part = chunk.strip()
            if not part:
                continue
            if ":" not in part:
                key = self._normalize_js_key(part)
                fields[key] = "unknown"
                continue
            key_part, value_part = part.split(":", maxsplit=1)
            key = self._normalize_js_key(key_part)
            fields[key] = self._infer_js_type(value_part.strip())
        return fields

    def _extract_object_as_string_map(self, expr: str) -> dict[str, str]:
        object_text = self._extract_outer_object(expr)
        if not object_text:
            return {}
        body = object_text[1:-1]
        chunks = self._split_top_level(body, ",")
        out: dict[str, str] = {}
        for chunk in chunks:
            part = chunk.strip()
            if not part or ":" not in part:
                continue
            key_part, value_part = part.split(":", maxsplit=1)
            key = self._normalize_js_key(key_part)
            out[key] = self._strip_wrapping_quotes(value_part.strip())
        return out

    def _extract_outer_object(self, expr: str) -> str:
        if not expr:
            return ""
        text = expr.strip()
        start = text.find("{")
        if start == -1:
            return ""
        depth = 0
        in_string: str | None = None
        escape = False
        for idx in range(start, len(text)):
            char = text[idx]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == in_string:
                    in_string = None
                continue
            if char in {'"', "'", "`"}:
                in_string = char
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
                if depth == 0:
                    return text[start : idx + 1]
        return ""

    def _infer_js_type(self, value: str) -> str:
        token = value.strip()
        if not token:
            return "unknown"
        lowered = token.lower()
        if lowered in {"true", "false"}:
            return "boolean"
        if lowered == "null":
            return "null"
        if token.startswith(('"', "'", "`")):
            return "string"
        if token.startswith("["):
            return "array"
        if token.startswith("{"):
            return "object"
        if re.match(r"^-?\d+(?:\.\d+)?$", token):
            return "number"
        return "unknown"

    def _find_option_value(self, object_expr: str, key: str) -> str | None:
        option_expr = self._find_option_expression(object_expr, key)
        if not option_expr:
            return None
        return self._strip_wrapping_quotes(option_expr.strip())

    def _find_option_expression(self, object_expr: str, key: str) -> str:
        if not object_expr:
            return ""
        regex = re.compile(rf"\b{re.escape(key)}\b\s*:\s*")
        match = regex.search(object_expr)
        if not match:
            return ""

        idx = match.end()
        depth_paren = 0
        depth_brace = 0
        depth_bracket = 0
        in_string: str | None = None
        escape = False

        while idx < len(object_expr):
            char = object_expr[idx]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == in_string:
                    in_string = None
                idx += 1
                continue

            if char in {'"', "'", "`"}:
                in_string = char
                idx += 1
                continue

            if char == "(":
                depth_paren += 1
            elif char == ")":
                depth_paren -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}":
                if depth_brace == 0 and depth_paren == 0 and depth_bracket == 0:
                    break
                depth_brace -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]":
                depth_bracket -= 1
            elif char == "," and depth_paren == 0 and depth_brace == 0 and depth_bracket == 0:
                break
            idx += 1

        return object_expr[match.end() : idx].strip()

    def _find_token_occurrences(self, content: str, token: str) -> list[int]:
        indexes: list[int] = []
        start = 0
        while True:
            idx = content.find(token, start)
            if idx == -1:
                break
            indexes.append(idx)
            start = idx + len(token)
        return indexes

    def _extract_balanced_arguments(self, content: str, open_paren_idx: int) -> str | None:
        if open_paren_idx >= len(content) or content[open_paren_idx] != "(":
            return None
        depth = 0
        in_string: str | None = None
        escape = False
        for idx in range(open_paren_idx, len(content)):
            char = content[idx]
            if in_string:
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == in_string:
                    in_string = None
                continue

            if char in {'"', "'", "`"}:
                in_string = char
                continue
            if char == "(":
                depth += 1
            elif char == ")":
                depth -= 1
                if depth == 0:
                    return content[open_paren_idx + 1 : idx]
        return None

    def _split_top_level(self, text: str, delimiter: str, maxsplit: int = -1) -> list[str]:
        parts: list[str] = []
        current: list[str] = []
        depth_paren = 0
        depth_brace = 0
        depth_bracket = 0
        in_string: str | None = None
        escape = False
        splits = 0

        for char in text:
            if in_string:
                current.append(char)
                if escape:
                    escape = False
                elif char == "\\":
                    escape = True
                elif char == in_string:
                    in_string = None
                continue

            if char in {'"', "'", "`"}:
                in_string = char
                current.append(char)
                continue

            if char == "(":
                depth_paren += 1
            elif char == ")":
                depth_paren -= 1
            elif char == "{":
                depth_brace += 1
            elif char == "}":
                depth_brace -= 1
            elif char == "[":
                depth_bracket += 1
            elif char == "]":
                depth_bracket -= 1

            if char == delimiter and depth_paren == 0 and depth_brace == 0 and depth_bracket == 0:
                if 0 <= maxsplit == splits:
                    current.append(char)
                    continue
                parts.append("".join(current))
                current = []
                splits += 1
            else:
                current.append(char)

        parts.append("".join(current))
        return parts

    def _strip_wrapping_quotes(self, value: str) -> str:
        text = value.strip()
        if len(text) >= 2 and text[0] == text[-1] and text[0] in {'"', "'", "`"}:
            return text[1:-1]
        return text

    def _normalize_js_key(self, token: str) -> str:
        key = token.strip()
        key = key.strip('"').strip("'").strip("`")
        key = key.replace("?", "").replace(".", "_")
        return key

    def _iter_source_files(self, repo_path: Path) -> list[Path]:
        files: list[Path] = []
        for path in repo_path.rglob("*"):
            if not path.is_file() or path.suffix not in SUPPORTED_SUFFIXES:
                continue
            if any(part in IGNORED_DIRS for part in path.parts):
                continue
            files.append(path)
        return files

    @staticmethod
    def _is_unresolved_payload(body_expr: str, extracted_fields: dict[str, str]) -> bool:
        """Return True when a body argument was provided but field extraction yielded nothing."""
        if not body_expr or not body_expr.strip():
            return False
        if extracted_fields:
            return False
        stripped = body_expr.strip()
        if stripped.startswith("{"):
            return False
        return True

    @staticmethod
    def _is_bare_identifier(url_expr: str) -> bool:
        """Return True when the URL expression is a plain variable name."""
        stripped = url_expr.strip()
        if not stripped:
            return False
        unquoted = stripped.strip("'\"`")
        return bool(_BARE_IDENTIFIER_RE.match(unquoted)) and "/" not in stripped

    @staticmethod
    def _is_non_config_url(url: str) -> bool:
        """Return True for URLs that are not application config (SVG xmlns, XML schemas, etc.)."""
        lowered = url.lower()
        return any(host in lowered for host in _NON_CONFIG_URL_HOSTS)

    def _line_of_index(self, content: str, index: int) -> int:
        return content.count("\n", 0, index) + 1
