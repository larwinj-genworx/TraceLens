"""Shared helpers for parsing LLM JSON responses into Issue objects."""
from __future__ import annotations

import json
from typing import Any

from src.observability.logging.setup import get_logger
from src.schemas.issues import ConfidenceBand, Issue, Severity

logger = get_logger(__name__)

_VALID_SEVERITIES = {s.value for s in Severity}


def parse_issues_from_response(raw: str, source: str) -> list[Issue]:
    """Parse the raw LLM text output into validated Issue objects.

    Handles both ``{"issues": [...]}`` and ``{"verified_issues": [...]}``
    envelope shapes produced by the different agent prompts.
    """
    payload = _safe_json_parse(raw)
    if payload is None:
        logger.warning("agent_parse_failed source=%s – could not parse JSON", source)
        return []

    items: list[dict[str, Any]] = []
    if isinstance(payload, dict):
        items = payload.get("issues", payload.get("verified_issues", []))
    if not isinstance(items, list):
        logger.warning("agent_parse_unexpected source=%s items_type=%s", source, type(items).__name__)
        return []

    issues: list[Issue] = []
    for idx, raw_item in enumerate(items):
        issue = _try_build_issue(raw_item, source, idx)
        if issue is not None:
            issues.append(issue)

    logger.info("agent_parsed source=%s raw_count=%d valid_count=%d", source, len(items), len(issues))
    return issues


def _try_build_issue(raw: dict[str, Any], source: str, idx: int) -> Issue | None:
    try:
        severity_val = str(raw.get("severity", "medium")).lower()
        if severity_val not in _VALID_SEVERITIES:
            severity_val = "medium"

        confidence = raw.get("confidence", 0.7)
        if not isinstance(confidence, (int, float)):
            confidence = 0.7
        confidence = max(0.0, min(1.0, float(confidence)))

        return Issue(
            type=str(raw.get("type", "unknown")),
            severity=Severity(severity_val),
            service=str(raw.get("service", "unknown")),
            endpoint=raw.get("endpoint"),
            file=raw.get("file"),
            line=raw.get("line"),
            description=str(raw.get("description", "")),
            evidence=raw.get("evidence") if isinstance(raw.get("evidence"), dict) else {},
            impact=str(raw.get("impact", "")),
            fix=str(raw.get("fix", "")),
            confidence=confidence,
            confidence_band=ConfidenceBand(str(raw.get("confidence_band", "heuristic")).lower())
            if str(raw.get("confidence_band", "heuristic")).lower() in {band.value for band in ConfidenceBand}
            else ConfidenceBand.HEURISTIC,
            advisory=bool(raw.get("advisory", False)),
            provenance=[str(item) for item in raw.get("provenance", []) if item] or [source],
            source=source,
        )
    except Exception:
        logger.warning("agent_issue_build_failed source=%s idx=%d", source, idx, exc_info=True)
        return None


def _safe_json_parse(text: str) -> dict[str, Any] | None:
    text = text.strip()
    try:
        return json.loads(text)
    except json.JSONDecodeError:
        pass

    start = text.find("{")
    end = text.rfind("}")
    if start != -1 and end > start:
        try:
            return json.loads(text[start : end + 1])
        except json.JSONDecodeError:
            pass

    return None
