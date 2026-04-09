"""Parse and normalize copy-pasted folder structure templates."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Literal


FolderTemplateFormat = Literal["kv_map", "tree", "yaml_like"]


@dataclass
class FolderTemplateParseError:
    line: int
    message: str
    content: str


@dataclass
class FolderTemplateParseResult:
    folder_structure: dict[str, str] = field(default_factory=dict)
    errors: list[FolderTemplateParseError] = field(default_factory=list)
    warnings: list[str] = field(default_factory=list)
    detected_format: FolderTemplateFormat = "kv_map"

    @property
    def is_valid(self) -> bool:
        return not self.errors


def normalize_role_id(value: str) -> str:
    normalized = value.strip().lower()
    normalized = normalized.replace("-", "_").replace(" ", "_")
    return "".join(ch for ch in normalized if ch.isalnum() or ch == "_")


def render_folder_structure_template(folder_structure: dict[str, str]) -> str:
    lines: list[str] = []
    for role_id, path in folder_structure.items():
        if not path:
            continue
        lines.append(f"{role_id}: {path}")
    return "\n".join(lines)


def parse_folder_structure_template(
    template: str,
    *,
    required_roles: list[str] | None = None,
    known_roles: list[str] | None = None,
    format_hint: FolderTemplateFormat | None = None,
) -> FolderTemplateParseResult:
    result = FolderTemplateParseResult()
    text = (template or "").strip()

    if not text:
        result.errors.append(
            FolderTemplateParseError(
                line=1,
                message="Folder structure template is empty.",
                content="",
            )
        )
        return result

    known = set(known_roles or [])
    required = set(required_roles or [])
    last_role: str | None = None
    has_arrow = False
    has_colon = False
    has_indented_path = False

    for line_no, raw_line in enumerate(text.splitlines(), start=1):
        stripped = raw_line.strip()
        if not stripped or stripped.startswith("#"):
            continue

        line = stripped
        if line.startswith("- ") or line.startswith("* "):
            line = line[2:].strip()

        parsed = _parse_role_path_line(line)
        if parsed is not None:
            role_raw, path = parsed
            role_id = normalize_role_id(role_raw)
            if not role_id:
                result.errors.append(
                    FolderTemplateParseError(
                        line=line_no,
                        message="Role identifier is empty.",
                        content=raw_line,
                    )
                )
                continue
            if not path:
                result.errors.append(
                    FolderTemplateParseError(
                        line=line_no,
                        message="Folder path is empty.",
                        content=raw_line,
                    )
                )
                continue

            if "->" in line or "=>" in line:
                has_arrow = True
            if ":" in line:
                has_colon = True

            if role_id in result.folder_structure:
                result.warnings.append(
                    f"Role '{role_id}' appears multiple times; using the latest definition (line {line_no})."
                )

            result.folder_structure[role_id] = _normalize_folder_path(path)
            last_role = role_id
            if known and role_id not in known:
                result.warnings.append(
                    f"Unknown role '{role_id}' at line {line_no}; it will be stored but not used by strict role checks."
                )
            continue

        if line.endswith(":") and "/" not in line:
            # Section headers like "Backend:" / "Frontend:" are allowed.
            last_role = None
            continue

        if last_role and _looks_like_path(line):
            has_indented_path = True
            if result.folder_structure.get(last_role):
                result.warnings.append(
                    f"Additional path for role '{last_role}' at line {line_no} ignored."
                )
            else:
                result.folder_structure[last_role] = _normalize_folder_path(line)
            continue

        result.errors.append(
            FolderTemplateParseError(
                line=line_no,
                message=(
                    "Invalid folder mapping line. Use 'role: path', 'role -> path', or 'role = path'."
                ),
                content=raw_line,
            )
        )

    if format_hint is not None:
        result.detected_format = format_hint
    elif has_indented_path:
        result.detected_format = "tree"
    elif has_colon:
        result.detected_format = "yaml_like"
    elif has_arrow:
        result.detected_format = "kv_map"
    else:
        result.detected_format = "kv_map"

    missing = [role for role in required if not result.folder_structure.get(role)]
    if missing:
        missing_list = ", ".join(sorted(missing))
        result.errors.append(
            FolderTemplateParseError(
                line=1,
                message=f"Missing required roles in template: {missing_list}",
                content="",
            )
        )

    return result


def _parse_role_path_line(line: str) -> tuple[str, str] | None:
    separators = ["->", "=>", ":", "="]
    for sep in separators:
        if sep not in line:
            continue
        left, right = line.split(sep, 1)
        role = left.strip()
        path = right.strip().strip("'\"")
        if role:
            return role, path
    return None


def _normalize_folder_path(path: str) -> str:
    value = path.strip().strip("'\"")
    while "//" in value:
        value = value.replace("//", "/")
    return value.rstrip("/")


def _looks_like_path(value: str) -> bool:
    trimmed = value.strip()
    return (
        "/" in trimmed
        or trimmed.startswith(".")
        or trimmed.startswith("src")
        or trimmed.startswith("app")
    )

