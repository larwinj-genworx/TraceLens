from __future__ import annotations

import json
from pathlib import Path

from pydantic import BaseModel, Field

from src.config.settings import PROJECT_ROOT
from src.constants.defaults import PUBLIC_PATH_MARKERS
from src.schemas.internal import FlowRuleDefinition


class FlowCatalog(BaseModel):
    version: str
    public_path_markers: list[str] = Field(default_factory=list)
    flows: list[FlowRuleDefinition] = Field(default_factory=list)


class FlowCatalogLoader:
    def __init__(self, catalog_path: Path | None = None) -> None:
        self.catalog_path = catalog_path or (PROJECT_ROOT / "src/config/flow_catalogs/mandatory_flows_v1.json")
        self._cache: FlowCatalog | None = None

    def load(self) -> FlowCatalog:
        if self._cache is not None:
            return self._cache

        payload = json.loads(self.catalog_path.read_text(encoding="utf-8"))
        catalog = FlowCatalog.model_validate(payload)

        if not catalog.public_path_markers:
            catalog.public_path_markers = sorted(PUBLIC_PATH_MARKERS)

        self._cache = catalog
        return catalog
