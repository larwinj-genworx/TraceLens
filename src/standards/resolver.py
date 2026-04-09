"""Resolve a TraceLensStandard into concrete checking configuration.

The resolver reads a user's standard (category selections + folder structure)
and merges them with the questions catalog to produce a flat ``ResolvedStandard``
that every downstream analyzer can consume without knowing about the catalog.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from src.config.settings import PROJECT_ROOT
from src.schemas.standards import TraceLensStandard

logger = logging.getLogger(__name__)

CATALOG_PATH = PROJECT_ROOT / "src" / "config" / "standards_catalog" / "questions_v1.json"


@dataclass
class CategoryResolution:
    """Resolved configuration for a single category."""

    category_id: str
    selected_style: str
    check_strategy: str
    evidence_markers: list[str]
    label: str = ""
    all_option_markers: list[str] = field(default_factory=list)
    required: bool = False


@dataclass
class StackResolution:
    """Resolved configuration for one technology stack."""

    stack_type: str
    categories: dict[str, CategoryResolution] = field(default_factory=dict)
    folder_expectations: dict[str, str] = field(default_factory=dict)

    def get_markers(self, category_id: str) -> list[str]:
        cat = self.categories.get(category_id)
        return cat.evidence_markers if cat else []

    def get_strategy(self, category_id: str) -> str:
        cat = self.categories.get(category_id)
        return cat.check_strategy if cat else ""

    def get_style(self, category_id: str) -> str:
        cat = self.categories.get(category_id)
        return cat.selected_style if cat else ""


@dataclass
class ResolvedStandard:
    """Fully resolved standard ready for consumption by analyzers."""

    standard_id: str
    name: str
    fastapi: StackResolution = field(default_factory=lambda: StackResolution(stack_type="fastapi"))
    react: StackResolution = field(default_factory=lambda: StackResolution(stack_type="react"))
    mandatory_rules_version: str = "mandatory_v1"

    # Convenience shortcuts for the most critical categories
    @property
    def auth_strategy(self) -> str:
        return self.fastapi.get_strategy("auth_style")

    @property
    def auth_markers(self) -> list[str]:
        return self.fastapi.get_markers("auth_style")

    @property
    def auth_style(self) -> str:
        return self.fastapi.get_style("auth_style")

    @property
    def authz_strategy(self) -> str:
        return self.fastapi.get_strategy("authz_model")

    @property
    def authz_markers(self) -> list[str]:
        return self.fastapi.get_markers("authz_model")

    @property
    def authz_enforcement_strategy(self) -> str:
        return self.fastapi.get_strategy("authz_enforcement")

    @property
    def authz_enforcement_markers(self) -> list[str]:
        return self.fastapi.get_markers("authz_enforcement")

    @property
    def ownership_strategy(self) -> str:
        return self.fastapi.get_strategy("ownership_protection")

    @property
    def ownership_markers(self) -> list[str]:
        return self.fastapi.get_markers("ownership_protection")

    @property
    def validation_strategy(self) -> str:
        return self.fastapi.get_strategy("request_validation")

    @property
    def validation_markers(self) -> list[str]:
        return self.fastapi.get_markers("request_validation")

    @property
    def error_handling_strategy(self) -> str:
        return self.fastapi.get_strategy("error_handling")

    @property
    def error_handling_markers(self) -> list[str]:
        return self.fastapi.get_markers("error_handling")

    @property
    def architecture_pattern(self) -> str:
        return self.fastapi.get_style("architecture_pattern")

    @property
    def persistence_pattern(self) -> str:
        return self.fastapi.get_style("persistence_pattern")

    @property
    def token_storage_style(self) -> str:
        return self.react.get_style("auth_token_storage")

    @property
    def token_storage_markers(self) -> list[str]:
        return self.react.get_markers("auth_token_storage")

    @property
    def http_client_style(self) -> str:
        return self.react.get_style("http_client")

    def has_standard(self) -> bool:
        return bool(self.fastapi.categories or self.react.categories)

    def to_prompt_context(self) -> dict[str, Any]:
        """Serialize into a dict suitable for injection into LLM prompts."""
        result: dict[str, Any] = {
            "standard_id": self.standard_id,
            "standard_name": self.name,
        }
        for stack_key, stack in [("fastapi", self.fastapi), ("react", self.react)]:
            stack_dict: dict[str, Any] = {}
            for cat_id, cat in stack.categories.items():
                stack_dict[cat_id] = {
                    "style": cat.selected_style,
                    "strategy": cat.check_strategy,
                    "markers": cat.evidence_markers,
                }
            if stack.folder_expectations:
                stack_dict["folder_structure"] = stack.folder_expectations
            if stack_dict:
                result[stack_key] = stack_dict
        return result


class StandardsResolver:
    """Resolves a TraceLensStandard into a ResolvedStandard."""

    def __init__(self) -> None:
        self._catalog: dict[str, Any] | None = None

    def _load_catalog(self) -> dict[str, Any]:
        if self._catalog is None:
            self._catalog = json.loads(CATALOG_PATH.read_text(encoding="utf-8"))
        return self._catalog

    def _build_option_index(
        self, stack_type: str
    ) -> tuple[dict[str, dict[str, dict[str, Any]]], dict[str, dict[str, Any]]]:
        """Build:
        - {category_id: {option_value: option_dict}} for fast lookup
        - {category_id: category_meta} for additional category metadata.
        """
        catalog = self._load_catalog()
        stack_data = catalog.get("stacks", {}).get(stack_type, {})
        index: dict[str, dict[str, dict[str, Any]]] = {}
        meta: dict[str, dict[str, Any]] = {}
        for cat in stack_data.get("categories", []):
            cat_id = cat["id"]
            index[cat_id] = {}
            for opt in cat.get("options", []):
                index[cat_id][opt["value"]] = opt
            all_markers: list[str] = []
            for opt in cat.get("options", []):
                for marker in opt.get("evidence_markers", []):
                    if marker not in all_markers:
                        all_markers.append(marker)
            meta[cat_id] = {
                "required": bool(cat.get("required", False)),
                "all_option_markers": all_markers,
            }
        return index, meta

    def resolve(self, standard: TraceLensStandard) -> ResolvedStandard:
        resolved = ResolvedStandard(
            standard_id=standard.standard_id,
            name=standard.name,
            mandatory_rules_version=standard.mandatory_rules_version,
        )

        for stack_config in standard.stacks:
            st = stack_config.stack_type
            option_index, category_meta = self._build_option_index(st)
            stack_resolution = StackResolution(stack_type=st)

            for cat_id, selected_value in stack_config.categories.items():
                if not selected_value:
                    continue
                opt_data = option_index.get(cat_id, {}).get(selected_value)
                if opt_data is None:
                    logger.warning(
                        "Unknown option %r for category %r in stack %r",
                        selected_value,
                        cat_id,
                        st,
                    )
                    stack_resolution.categories[cat_id] = CategoryResolution(
                        category_id=cat_id,
                        selected_style=selected_value,
                        check_strategy="",
                        evidence_markers=[],
                        all_option_markers=category_meta.get(cat_id, {}).get(
                            "all_option_markers", []
                        ),
                        required=bool(category_meta.get(cat_id, {}).get("required", False)),
                    )
                    continue

                stack_resolution.categories[cat_id] = CategoryResolution(
                    category_id=cat_id,
                    selected_style=selected_value,
                    check_strategy=opt_data.get("check_strategy", ""),
                    evidence_markers=opt_data.get("evidence_markers", []),
                    label=opt_data.get("label", ""),
                    all_option_markers=category_meta.get(cat_id, {}).get(
                        "all_option_markers", []
                    ),
                    required=bool(category_meta.get(cat_id, {}).get("required", False)),
                )

            stack_resolution.folder_expectations = dict(
                stack_config.folder_structure
            )

            if st == "fastapi":
                resolved.fastapi = stack_resolution
            elif st == "react":
                resolved.react = stack_resolution

        return resolved
