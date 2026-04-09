"""Unified marker management for TraceLens standards.

The MarkerRegistry consolidates marker lookups from three sources
(in priority order):

1. User's resolved standard (highest priority)
2. Questions catalog defaults
3. Mandatory flow catalog markers (floor)

All evidence collectors, canonicalization utilities, and filters should
use this registry instead of hardcoded marker sets.
"""

from __future__ import annotations

import logging
import re
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from src.flows.catalog import FlowCatalog
    from src.standards.resolver import ResolvedStandard

logger = logging.getLogger(__name__)

_SELF_SERVICE_PATTERNS = re.compile(
    r"/(me|my|self|profile)(/|$)", re.IGNORECASE
)

_ADMIN_PATH_INDICATORS = frozenset({
    "/admin/", "/admin-",
    "/system/", "/config/",
    "/settings/", "/management/",
})

_GLOBAL_RESOURCE_PATH_INDICATORS = frozenset({
    "severity", "sla", "role", "permission",
    "config", "setting", "template", "category",
    "status", "priority", "type", "tag",
})


class MarkerRegistry:
    """Single source of truth for all marker lookups."""

    def __init__(
        self,
        resolved: ResolvedStandard | None = None,
        flow_catalog: FlowCatalog | None = None,
    ) -> None:
        self._resolved = resolved
        self._flow_catalog = flow_catalog

        self._public_paths: list[str] | None = None
        self._auth_markers: list[str] | None = None
        self._authz_markers: list[str] | None = None
        self._ownership_markers: list[str] | None = None

    # ── Public path detection ──────────────────────────────────────────────

    def public_path_markers(self) -> list[str]:
        if self._public_paths is not None:
            return self._public_paths

        markers: list[str] = []

        # Floor: flow catalog public path markers
        if self._flow_catalog and self._flow_catalog.public_path_markers:
            markers.extend(self._flow_catalog.public_path_markers)

        # User-declared public paths (highest priority, additive)
        if self._resolved:
            from src.schemas.standards import TraceLensStandard
            # Check if the original standard had public_paths
            # (resolved doesn't carry them, but we can add via init)
            pass

        # Additional well-known auth-flow paths
        _EXTRA_AUTH_FLOW = [
            "/auth/refresh",
            "/auth/logout",
            "/auth/forgot-password",
            "/auth/reset-password",
            "/auth/change-password",
            "/users/me/change-password",
            "/auth/verify",
            "/auth/verify-email",
            "/auth/resend-verification",
            "/sse/",
        ]
        for path in _EXTRA_AUTH_FLOW:
            if path not in markers:
                markers.append(path)

        self._public_paths = sorted(set(markers))
        return self._public_paths

    def is_public_path(self, path: str, route_intent: str | None = None) -> bool:
        if route_intent in ("public_meta", "auth_entry"):
            return True

        normalized = path.lower().rstrip("/")
        if not normalized:
            normalized = "/"

        for marker in self.public_path_markers():
            marker_norm = marker.lower().rstrip("/")
            if not marker_norm:
                if normalized == "/":
                    return True
                continue
            if normalized == marker_norm:
                return True
            if normalized.startswith(marker_norm + "/") or normalized.startswith(marker_norm):
                if marker_norm.endswith("/") or len(normalized) == len(marker_norm):
                    return True
            # prefix-based: /health matches /healthz, /health/check
            if normalized.startswith(marker_norm):
                return True

        return False

    def is_auth_flow_path(self, path: str) -> bool:
        normalized = path.lower().rstrip("/")
        _AUTH_FLOW_PATTERNS = (
            "/login", "/signup", "/register", "/token",
            "/forgot", "/password/reset", "/password/forgot",
            "/password/verify", "/verify", "/otp", "/invite/accept",
            "/auth/refresh", "/auth/logout", "/auth/forgot",
            "/auth/reset", "/auth/verify", "/auth/change",
        )
        return any(marker in normalized for marker in _AUTH_FLOW_PATTERNS)

    # ── Auth markers ───────────────────────────────────────────────────────

    def auth_markers(self) -> list[str]:
        if self._auth_markers is not None:
            return self._auth_markers

        markers: list[str] = []

        # From resolved standard
        if self._resolved:
            markers.extend(self._resolved.auth_markers)

        # From flow catalog (authn_flow covered markers)
        if self._flow_catalog:
            for flow in self._flow_catalog.flows:
                if flow.id == "authn_flow":
                    for m in flow.covered_markers:
                        if m not in markers:
                            markers.append(m)
                    break

        self._auth_markers = markers
        return self._auth_markers

    # ── Authz markers ──────────────────────────────────────────────────────

    def authz_markers(self) -> list[str]:
        if self._authz_markers is not None:
            return self._authz_markers

        markers: list[str] = []

        if self._resolved:
            markers.extend(self._resolved.authz_markers)
            markers.extend(self._resolved.authz_enforcement_markers)

        if self._flow_catalog:
            for flow in self._flow_catalog.flows:
                if flow.id == "authz_flow":
                    for m in flow.covered_markers:
                        if m not in markers:
                            markers.append(m)
                    break

        self._authz_markers = markers
        return self._authz_markers

    # ── Ownership markers ──────────────────────────────────────────────────

    def ownership_markers(self) -> list[str]:
        if self._ownership_markers is not None:
            return self._ownership_markers

        markers: list[str] = []

        if self._resolved:
            markers.extend(self._resolved.ownership_markers)

        if self._flow_catalog:
            for flow in self._flow_catalog.flows:
                if flow.id == "ownership_flow":
                    for m in flow.covered_markers:
                        if m not in markers:
                            markers.append(m)
                    break

        self._ownership_markers = markers
        return self._ownership_markers

    # ── Admin / global resource helpers ─────────────────────────────────────

    @staticmethod
    def is_self_service_path(path: str) -> bool:
        return bool(_SELF_SERVICE_PATTERNS.search(path.lower()))

    @staticmethod
    def is_admin_resource_path(path: str) -> bool:
        lowered = path.lower()
        return any(indicator in lowered for indicator in _ADMIN_PATH_INDICATORS)

    @staticmethod
    def is_global_resource_path(path: str) -> bool:
        segments = [s for s in path.lower().split("/") if s and not s.startswith("{")]
        for seg in segments:
            if seg in _GLOBAL_RESOURCE_PATH_INDICATORS:
                return True
            # Also match compound segments like "severity-keywords"
            sub_parts = seg.replace("-", "_").split("_")
            if any(part in _GLOBAL_RESOURCE_PATH_INDICATORS for part in sub_parts):
                return True
        return False

    @staticmethod
    def is_admin_only_endpoint(dep_classifications: list[str]) -> bool:
        return any("authz" in dc and "admin" in dc.lower() for dc in dep_classifications)

    def set_user_public_paths(self, paths: list[str]) -> None:
        self._public_paths = None
        base = self.public_path_markers()
        for p in paths:
            if p not in base:
                base.append(p)
        self._public_paths = base
