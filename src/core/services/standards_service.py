"""TraceLens standards management service."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from src.config.settings import PROJECT_ROOT
from src.schemas.standards import (
    MandatoryRulesCatalog,
    TraceLensStandard,
    TraceLensStandardSummary,
)
from src.standards.folder_template_parser import (
    parse_folder_structure_template,
    render_folder_structure_template,
)

STANDARDS_DIR = PROJECT_ROOT / ".data" / "standards"
CATALOG_DIR = PROJECT_ROOT / "src" / "config" / "standards_catalog"


class TraceLensStandardsService:
    """CRUD operations for TraceLens standards plus catalog access."""

    def __init__(self) -> None:
        STANDARDS_DIR.mkdir(parents=True, exist_ok=True)

    def list_standards(self) -> list[TraceLensStandardSummary]:
        results: list[TraceLensStandardSummary] = []
        for path in sorted(STANDARDS_DIR.glob("*.json")):
            try:
                data = json.loads(path.read_text(encoding="utf-8"))
                standard = TraceLensStandard.model_validate(data)
                results.append(
                    TraceLensStandardSummary(
                        standard_id=standard.standard_id,
                        name=standard.name,
                        description=standard.description,
                        version=standard.version,
                        stack_types=[s.stack_type for s in standard.stacks],
                        created_at=standard.created_at,
                        updated_at=standard.updated_at,
                    )
                )
            except Exception:
                continue
        return results

    def get_standard(self, standard_id: str) -> TraceLensStandard:
        path = STANDARDS_DIR / f"{standard_id}.json"
        if not path.exists():
            raise ValueError(f"Standard '{standard_id}' not found.")
        data = json.loads(path.read_text(encoding="utf-8"))
        return TraceLensStandard.model_validate(data)

    def save_standard(self, standard: TraceLensStandard) -> TraceLensStandard:
        self._normalize_standard_folder_structures(standard)
        standard.updated_at = datetime.now(timezone.utc)
        path = STANDARDS_DIR / f"{standard.standard_id}.json"
        is_new = not path.exists()
        if is_new:
            standard.created_at = datetime.now(timezone.utc)
        path.write_text(
            standard.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return standard

    def update_standard(
        self, standard_id: str, standard: TraceLensStandard
    ) -> TraceLensStandard:
        path = STANDARDS_DIR / f"{standard_id}.json"
        if not path.exists():
            raise ValueError(f"Standard '{standard_id}' not found.")
        self._normalize_standard_folder_structures(standard)
        if standard_id != standard.standard_id:
            (STANDARDS_DIR / f"{standard_id}.json").unlink(missing_ok=True)
        standard.updated_at = datetime.now(timezone.utc)
        target = STANDARDS_DIR / f"{standard.standard_id}.json"
        target.write_text(
            standard.model_dump_json(indent=2),
            encoding="utf-8",
        )
        return standard

    def delete_standard(self, standard_id: str) -> None:
        path = STANDARDS_DIR / f"{standard_id}.json"
        if not path.exists():
            raise ValueError(f"Standard '{standard_id}' not found.")
        path.unlink()

    def get_questions_catalog(self) -> dict[str, Any]:
        path = CATALOG_DIR / "questions_v1.json"
        return json.loads(path.read_text(encoding="utf-8"))

    def get_mandatory_rules(self) -> MandatoryRulesCatalog:
        path = CATALOG_DIR / "mandatory_rules_v1.json"
        data = json.loads(path.read_text(encoding="utf-8"))
        return MandatoryRulesCatalog.model_validate(data)

    def _normalize_standard_folder_structures(
        self, standard: TraceLensStandard
    ) -> None:
        catalog = self.get_questions_catalog()
        stacks_cfg = catalog.get("stacks", {})

        for stack in standard.stacks:
            stack_cfg = stacks_cfg.get(stack.stack_type, {})
            required_roles = [
                role.get("id", "")
                for role in stack_cfg.get("folder_roles", [])
                if role.get("id")
            ]

            template = (stack.folder_structure_template or "").strip()
            if template:
                parsed = parse_folder_structure_template(
                    template,
                    required_roles=required_roles,
                    known_roles=required_roles,
                    format_hint=stack.folder_structure_format,
                )
                if parsed.errors:
                    error_text = "; ".join(
                        f"line {err.line}: {err.message}" for err in parsed.errors
                    )
                    raise ValueError(
                        f"Invalid folder structure template for stack '{stack.stack_type}': {error_text}"
                    )
                stack.folder_structure = parsed.folder_structure
                stack.folder_structure_format = parsed.detected_format
                stack.folder_structure_template = template
                continue

            # Backward compatibility for standards saved before template support.
            if stack.folder_structure:
                missing = [
                    role for role in required_roles if not stack.folder_structure.get(role)
                ]
                if missing:
                    missing_text = ", ".join(sorted(missing))
                    raise ValueError(
                        f"Missing required folder roles for stack '{stack.stack_type}': {missing_text}"
                    )
                stack.folder_structure_template = render_folder_structure_template(
                    stack.folder_structure
                )
                if not stack.folder_structure_format:
                    stack.folder_structure_format = "kv_map"
                continue

            raise ValueError(
                f"Folder structure template is required for stack '{stack.stack_type}'."
            )
