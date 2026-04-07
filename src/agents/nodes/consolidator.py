from __future__ import annotations

import re
from collections import defaultdict
from typing import Any

from src.agents.state import AgentState
from src.observability.logging.setup import get_logger
from src.schemas.issues import Issue, Severity

logger = get_logger(__name__)

# Strip the HTTP method prefix (e.g. "GET ", "POST ") from an endpoint string.
_METHOD_RE = re.compile(r"^(?:GET|POST|PUT|PATCH|DELETE|OPTIONS|HEAD|WS)\s+", re.IGNORECASE)


def _path_of(endpoint: str | None) -> str:
    """Return just the path portion of 'METHOD /path'."""
    if not endpoint:
        return ""
    return _METHOD_RE.sub("", endpoint).strip()


def _merge_catch_all(issues: list[Issue]) -> list[Issue]:
    """Merge issues that differ only in the HTTP method on the same route.

    When a single catch-all handler (e.g. ``/process/{path:path}``) is
    registered for every HTTP verb, all analysts emit one ``missing_auth``
    (or similar) issue per verb — all pointing at the same file + line.
    Collapsing them into one issue with endpoint ``* /path`` keeps the report
    readable without losing information.

    Merge criteria (all must match):
      - same ``type``
      - same ``service``
      - same ``file``
      - same ``line``
      - path portion after stripping method is identical
    """
    # Group by (type, service, file, line, path)
    GroupKey = tuple[str, str, str | None, int | None, str]
    groups: dict[GroupKey, list[Issue]] = defaultdict(list)
    for issue in issues:
        path = _path_of(issue.endpoint)
        gk: GroupKey = (issue.type, issue.service, issue.file, issue.line, path)
        groups[gk].append(issue)

    merged: list[Issue] = []
    for (itype, svc, file, line, path), group in groups.items():
        if len(group) == 1:
            merged.append(group[0])
            continue

        # Pick the representative with the highest confidence as the base.
        base = max(group, key=lambda i: i.confidence)
        methods = sorted({
            m.group(0).strip()
            for i in group
            if i.endpoint and (m := _METHOD_RE.match(i.endpoint))
        })
        all_methods = ", ".join(methods) if methods else "*"

        merged_issue = base.model_copy(update={
            "endpoint": f"[{all_methods}] {path}" if path else base.endpoint,
            "evidence": {
                **base.evidence,
                "merged_methods": methods,
                "original_endpoint_count": len(group),
            },
            "description": (
                f"{base.description} (applies to {len(group)} HTTP methods: {all_methods})"
            ),
        })
        merged.append(merged_issue)

    return merged


def consolidate_issues(state: AgentState) -> dict[str, Any]:
    """Deterministic node: merge issues from all analyst agents, deduplicate,
    and keep the highest-confidence variant for each unique key."""
    security: list[Issue] = state.get("security_issues", [])
    integration: list[Issue] = state.get("integration_issues", [])
    quality: list[Issue] = state.get("quality_issues", [])

    all_issues = security + integration + quality
    logger.info(
        "consolidator started security=%d integration=%d quality=%d total=%d",
        len(security),
        len(integration),
        len(quality),
        len(all_issues),
    )

    # Primary dedup: keep highest confidence per (type, service, endpoint).
    best: dict[tuple[str, str, str | None], Issue] = {}
    for issue in all_issues:
        key = (issue.type, issue.service, issue.endpoint)
        existing = best.get(key)
        if existing is None or issue.confidence > existing.confidence:
            best[key] = issue

    # Secondary dedup: merge catch-all routes that produced one issue per
    # HTTP method for the same handler file + line.
    deduped = _merge_catch_all(list(best.values()))

    consolidated = sorted(
        deduped,
        key=lambda i: (
            {"critical": 0, "high": 1, "medium": 2}.get(i.severity.value, 3),
            -i.confidence,
            i.type,
            i.service,
        ),
    )

    removed = len(all_issues) - len(consolidated)
    logger.info(
        "consolidator done unique=%d (removed %d duplicates, %d method-merged)",
        len(consolidated),
        removed,
        len(best) - len(deduped),
    )
    return {"consolidated_issues": consolidated}
