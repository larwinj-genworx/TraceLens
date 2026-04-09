"""TraceLens Standards schema definitions."""

from __future__ import annotations

from datetime import datetime
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator


class StackConfig(BaseModel):
    """Configuration for one technology stack (fastapi or react)."""

    stack_type: Literal["fastapi", "react"]
    categories: dict[str, str] = Field(
        default_factory=dict,
        description="Mapping of category_id to selected style value.",
    )
    folder_structure: dict[str, str] = Field(
        default_factory=dict,
        description="Mapping of role name to folder path pattern.",
    )
    folder_structure_template: str = Field(
        default="",
        description="Raw copy-pasted folder structure template provided by the user.",
    )
    folder_structure_format: Literal["kv_map", "tree", "yaml_like"] = Field(
        default="kv_map",
        description="Detected or user-selected template format for folder structure parsing.",
    )
    custom_notes: list[str] = Field(default_factory=list)


class TraceLensStandard(BaseModel):
    """A user-defined TraceLens standard combining both stacks."""

    standard_id: str = Field(min_length=1, max_length=120)
    name: str = Field(min_length=1, max_length=200)
    description: str = Field(default="")
    version: int = Field(default=1, ge=1)
    stacks: list[StackConfig] = Field(
        min_length=1,
        max_length=2,
        description="Stack configurations (fastapi and/or react).",
    )
    mandatory_rules_version: str = Field(default="mandatory_v1")
    public_paths: list[str] = Field(
        default_factory=list,
        description="User-declared public paths that should skip auth/authz checks.",
    )
    created_at: datetime = Field(default_factory=lambda: datetime.utcnow())
    updated_at: datetime = Field(default_factory=lambda: datetime.utcnow())

    @field_validator("standard_id")
    @classmethod
    def validate_standard_id(cls, value: str) -> str:
        import re

        value = value.strip()
        if not re.match(r"^[a-z0-9][a-z0-9_-]{0,118}[a-z0-9]?$", value):
            raise ValueError(
                "standard_id must be lowercase alphanumeric with optional hyphens/underscores."
            )
        return value


class TraceLensStandardSummary(BaseModel):
    """Lightweight listing representation."""

    standard_id: str
    name: str
    description: str
    version: int
    stack_types: list[str]
    created_at: datetime
    updated_at: datetime


class TraceLensStandardListResponse(BaseModel):
    standards: list[TraceLensStandardSummary]


class CategoryOption(BaseModel):
    value: str
    label: str
    evidence_markers: list[str] = Field(default_factory=list)
    check_strategy: str = ""


class CategoryQuestion(BaseModel):
    id: str
    label: str
    description: str
    required: bool = True
    options: list[CategoryOption]


class FolderRoleDefinition(BaseModel):
    id: str
    label: str
    description: str
    placeholder: str = ""


class StackQuestionsCatalog(BaseModel):
    categories: list[CategoryQuestion]
    folder_roles: list[FolderRoleDefinition]


class QuestionsCatalog(BaseModel):
    version: str
    stacks: dict[str, StackQuestionsCatalog]


class MandatoryRule(BaseModel):
    id: str
    title: str
    description: str
    severity: str
    applies_to: str


class MandatoryRulesCatalog(BaseModel):
    version: str
    rules: list[MandatoryRule]
