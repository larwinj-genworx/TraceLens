from __future__ import annotations

import json
from typing import Any

from langchain_core.messages import HumanMessage, SystemMessage

from src.agents.llm_client import RateLimitedGroqClient
from src.agents.nodes.parsing import parse_issues_from_response
from src.agents.prompts.reviewer import CROSS_REVIEWER_SYSTEM
from src.agents.state import AgentState
from src.config.settings import settings
from src.observability.logging.setup import get_logger
from src.schemas.issues import Issue

logger = get_logger(__name__)

SOURCE = "cross_reviewer"
_MAX_CANDIDATES_CHARS = 12_000
_MAX_EVIDENCE_CHARS = 12_000
_BATCH_SIZE = 10
_BATCH_THRESHOLD = 15

_FLOW_ID_TO_ISSUE_TYPE: dict[str, str] = {
    "authn_flow": "missing_auth",
    "authz_flow": "missing_authz_flow",
    "ownership_flow": "missing_ownership_check",
    "request_validation_flow": "missing_validation",
    "response_contract_flow": "missing_response_contract_flow",
    "error_handling_flow": "missing_error_handling_flow",
    "input_sanitization_flow": "missing_input_sanitization_flow",
    "secret_pii_protection_flow": "missing_secret_pii_protection_flow",
    "rate_limit_flow": "missing_rate_limit_flow",
    "audit_trace_flow": "missing_audit_trace_flow",
    "idempotency_tx_flow": "missing_idempotency_tx_flow",
}


def _build_deterministic_keys(
    full_evidence: dict[str, Any],
) -> set[tuple[str, str | None]]:
    """Build a set of (issue_type, endpoint) from flow_coverage entries with
    status=missing.  These represent issues backed by deterministic static
    analysis and should be protected from LLM removal."""
    keys: set[tuple[str, str | None]] = set()
    for item in full_evidence.get("flow_coverage", []):
        if item.get("status") != "missing":
            continue
        if float(item.get("confidence", 0.0)) < 0.75:
            continue
        flow_id = item.get("flow", "")
        issue_type = _FLOW_ID_TO_ISSUE_TYPE.get(flow_id, flow_id)
        endpoint = item.get("ep")
        keys.add((issue_type, endpoint))
    return keys


def _tag_deterministic(
    candidates: list[dict[str, Any]],
    det_keys: set[tuple[str, str | None]],
) -> None:
    """Mutate candidate dicts in-place to add deterministic_backing flag."""
    for c in candidates:
        key = (c.get("type", ""), c.get("endpoint"))
        c["deterministic_backing"] = key in det_keys


async def review_issues(state: AgentState) -> dict[str, Any]:
    """LangGraph node: cross-review all consolidated issues against the full
    evidence, removing false positives and adjusting confidence."""
    consolidated: list[Issue] = state.get("consolidated_issues", [])
    full_evidence: dict[str, Any] = state["evidence_package"]["full"]
    standards_ctx: dict[str, Any] = state.get("standards_context", {})
    logger.info("cross_reviewer started candidates=%d", len(consolidated))

    if not consolidated:
        logger.info("cross_reviewer skipped – no candidates")
        return {"reviewed_issues": []}

    det_keys = _build_deterministic_keys(full_evidence)
    logger.info("cross_reviewer deterministic_keys=%d", len(det_keys))

    candidates_payload = _build_candidates_payload(consolidated, det_keys)
    det_keys |= _build_standards_backed_keys(candidates_payload)
    _tag_deterministic(candidates_payload, det_keys)
    evidence_summary = _compact_evidence_summary(full_evidence)

    if len(consolidated) > _BATCH_THRESHOLD:
        reviewed = await _batched_review(
            candidates_payload,
            evidence_summary,
            det_keys,
            consolidated,
            standards_ctx,
        )
    else:
        reviewed = await _single_review(
            candidates_payload,
            evidence_summary,
            det_keys,
            consolidated,
            standards_ctx,
        )

    _log_review_delta(len(consolidated), len(reviewed))
    return {"reviewed_issues": reviewed}


def _build_candidates_payload(
    consolidated: list[Issue],
    det_keys: set[tuple[str, str | None]],
) -> list[dict[str, Any]]:
    payload = [
        {
            "type": issue.type,
            "severity": issue.severity.value,
            "service": issue.service,
            "endpoint": issue.endpoint,
            "description": issue.description,
            "impact": issue.impact,
            "fix": issue.fix,
            "confidence": round(issue.confidence, 2),
            "confidence_band": issue.confidence_band.value,
            "advisory": issue.advisory,
            "source": issue.source,
            "provenance": issue.provenance,
        }
        for issue in consolidated
    ]
    _tag_deterministic(payload, det_keys)
    return payload


async def _single_review(
    candidates_payload: list[dict[str, Any]],
    evidence_summary: dict[str, Any],
    det_keys: set[tuple[str, str | None]],
    original_consolidated: list[Issue],
    standards_ctx: dict[str, Any],
) -> list[Issue]:
    """Review all candidates in a single LLM call."""
    candidates_text = json.dumps(candidates_payload, indent=None, default=str, ensure_ascii=False)
    if len(candidates_text) > _MAX_CANDIDATES_CHARS:
        candidates_text = candidates_text[:_MAX_CANDIDATES_CHARS] + " ...]"

    evidence_text = json.dumps(evidence_summary, indent=None, default=str, ensure_ascii=False)
    if len(evidence_text) > _MAX_EVIDENCE_CHARS:
        evidence_text = evidence_text[:_MAX_EVIDENCE_CHARS] + " ..."
    standards_text = json.dumps(standards_ctx, indent=None, default=str, ensure_ascii=False)
    if len(standards_text) > 3000:
        standards_text = standards_text[:3000] + " ..."

    logger.info(
        "cross_reviewer payload candidates_chars=%d evidence_chars=%d",
        len(candidates_text),
        len(evidence_text),
    )

    user_content = (
        "CANDIDATE ISSUES:\n" + candidates_text
        + "\n\nEVIDENCE SUMMARY:\n" + evidence_text
        + "\n\nSELECTED STANDARD CONTEXT:\n" + standards_text
        + "\n\nRULE: Do not remove deterministic standards-backed violations unless contradictory evidence is explicit."
    )

    client = RateLimitedGroqClient(model=settings.groq_reviewer_model)
    messages = [
        SystemMessage(content=CROSS_REVIEWER_SYSTEM),
        HumanMessage(content=user_content),
    ]

    try:
        raw_response = await client.invoke(messages)
        reviewed = parse_issues_from_response(raw_response, SOURCE)
    except Exception:
        logger.exception("cross_reviewer_failed – falling back to consolidated issues")
        reviewed = original_consolidated

    reviewed = _reinject_deterministic(reviewed, original_consolidated, det_keys)
    _restore_location_from_originals(reviewed, original_consolidated)
    return reviewed


async def _batched_review(
    candidates_payload: list[dict[str, Any]],
    evidence_summary: dict[str, Any],
    det_keys: set[tuple[str, str | None]],
    original_consolidated: list[Issue],
    standards_ctx: dict[str, Any],
) -> list[Issue]:
    """Split large candidate sets into batches and review each separately."""
    batches: list[list[dict[str, Any]]] = []
    for i in range(0, len(candidates_payload), _BATCH_SIZE):
        batches.append(candidates_payload[i : i + _BATCH_SIZE])

    logger.info("cross_reviewer batching %d candidates into %d batches", len(candidates_payload), len(batches))

    all_reviewed: list[Issue] = []
    consolidated_index: dict[tuple[str, str | None], Issue] = {
        (iss.type, iss.endpoint): iss for iss in original_consolidated
    }

    evidence_text = json.dumps(evidence_summary, indent=None, default=str, ensure_ascii=False)
    if len(evidence_text) > _MAX_EVIDENCE_CHARS:
        evidence_text = evidence_text[:_MAX_EVIDENCE_CHARS] + " ..."
    standards_text = json.dumps(standards_ctx, indent=None, default=str, ensure_ascii=False)
    if len(standards_text) > 3000:
        standards_text = standards_text[:3000] + " ..."

    for batch_idx, batch in enumerate(batches):
        batch_text = json.dumps(batch, indent=None, default=str, ensure_ascii=False)
        if len(batch_text) > _MAX_CANDIDATES_CHARS:
            batch_text = batch_text[:_MAX_CANDIDATES_CHARS] + " ...]"

        logger.info("cross_reviewer batch %d/%d candidates=%d chars=%d", batch_idx + 1, len(batches), len(batch), len(batch_text))

        user_content = (
            f"CANDIDATE ISSUES (batch {batch_idx + 1}/{len(batches)}):\n" + batch_text
            + "\n\nEVIDENCE SUMMARY:\n" + evidence_text
            + "\n\nSELECTED STANDARD CONTEXT:\n" + standards_text
            + "\n\nRULE: Do not remove deterministic standards-backed violations unless contradictory evidence is explicit."
        )

        client = RateLimitedGroqClient(model=settings.groq_reviewer_model)
        messages = [
            SystemMessage(content=CROSS_REVIEWER_SYSTEM),
            HumanMessage(content=user_content),
        ]

        try:
            raw_response = await client.invoke(messages)
            batch_reviewed = parse_issues_from_response(raw_response, SOURCE)
            all_reviewed.extend(batch_reviewed)
        except Exception:
            logger.exception("cross_reviewer batch %d failed – keeping originals for this batch", batch_idx + 1)
            batch_originals = [
                consolidated_index.get((c["type"], c.get("endpoint")), None)
                for c in batch
            ]
            all_reviewed.extend([o for o in batch_originals if o is not None])

    all_reviewed = _reinject_deterministic(all_reviewed, original_consolidated, det_keys)
    _restore_location_from_originals(all_reviewed, original_consolidated)
    return all_reviewed


def _restore_location_from_originals(
    reviewed: list[Issue],
    original: list[Issue],
) -> None:
    """Mutate reviewed issues in-place: copy file/line from the matching
    original consolidated issue when the LLM output omitted them.

    Matching key: (type, service, endpoint).  A secondary fallback matches
    on (type, service) alone when endpoint is None in the reviewed issue, to
    handle cases where the LLM drops or paraphrases the endpoint string.
    """
    primary_index: dict[tuple[str, str, str | None], Issue] = {
        (o.type, o.service, o.endpoint): o for o in original
    }
    secondary_index: dict[tuple[str, str], Issue] = {}
    for o in original:
        key2 = (o.type, o.service)
        if key2 not in secondary_index:
            secondary_index[key2] = o

    for issue in reviewed:
        if issue.file is not None:
            continue
        match = primary_index.get((issue.type, issue.service, issue.endpoint))
        if match is None:
            match = secondary_index.get((issue.type, issue.service))
        if match:
            issue.file = match.file
            issue.line = match.line
            issue.provenance = sorted(set(issue.provenance + match.provenance + [SOURCE]))


def _reinject_deterministic(
    reviewed: list[Issue],
    original: list[Issue],
    det_keys: set[tuple[str, str | None]],
) -> list[Issue]:
    """Re-inject any deterministic-backed issues that the LLM dropped."""
    reviewed_keys: set[tuple[str, str | None]] = {
        (iss.type, iss.endpoint) for iss in reviewed
    }

    reinjected = 0
    for orig in original:
        key = (orig.type, orig.endpoint)
        if key in det_keys and key not in reviewed_keys:
            logger.warning(
                "cross_reviewer re-injecting deterministic issue type=%s endpoint=%s",
                orig.type,
                orig.endpoint,
            )
            reviewed.append(orig)
            reviewed_keys.add(key)
            reinjected += 1

    if reinjected:
        logger.info("cross_reviewer re-injected %d deterministic issues", reinjected)
    return reviewed


def _build_standards_backed_keys(
    candidates_payload: list[dict[str, Any]],
) -> set[tuple[str, str | None]]:
    keys: set[tuple[str, str | None]] = set()
    for candidate in candidates_payload:
        issue_type = candidate.get("type", "")
        endpoint = candidate.get("endpoint")
        source = (candidate.get("source") or "").lower()
        provenance = [str(item).lower() for item in candidate.get("provenance", [])]
        if issue_type.startswith("standards_violation_"):
            keys.add((issue_type, endpoint))
            continue
        if source == "standards_engine" or "standards_engine" in provenance:
            keys.add((issue_type, endpoint))
    return keys


def _compact_evidence_summary(full: dict[str, Any]) -> dict[str, Any]:
    """Build an evidence digest for the reviewer with enough detail
    to verify whether candidate issues are grounded."""
    summary: dict[str, Any] = {}

    endpoints = full.get("endpoints", [])
    if endpoints:
        summary["endpoint_count"] = len(endpoints)
        summary["endpoints"] = [
            {
                "svc": e.get("svc"),
                "path": e.get("path"),
                "canonical_path": e.get("canonical_path"),
                "method": e.get("method"),
                "deps": e.get("deps", []),
                "auth_mode": e.get("auth_mode"),
                "ownership_mode": e.get("ownership_mode"),
                "route_intent": e.get("route_intent"),
                "sensitive": e.get("sensitive", []),
                "ws": e.get("ws", False),
                "req_fields": e.get("req_fields"),
            }
            for e in endpoints[:40]
        ]

    matches = full.get("graph_matches", [])
    if matches:
        summary["match_count"] = len(matches)
        summary["graph_matches"] = [
            {
                "fe_url": m.get("fe_url"),
                "fe_canonical_path": m.get("fe_canonical_path"),
                "fe_method": m.get("fe_method"),
                "be_path": m.get("be_path"),
                "be_canonical_path": m.get("be_canonical_path"),
                "be_method": m.get("be_method"),
                "payload_resolution": m.get("payload_resolution"),
                "fe_payload": m.get("fe_payload", []),
            }
            for m in matches[:15]
        ]

    unmatched = full.get("unmatched_calls", [])
    if unmatched:
        summary["unmatched"] = [
            {
                "url": u.get("url"),
                "canonical_path": u.get("canonical_path"),
                "method": u.get("method"),
                "svc": u.get("svc"),
                "payload_resolution": u.get("payload_resolution"),
            }
            for u in unmatched[:20]
        ]

    contracts = full.get("contract_violations", [])
    if contracts:
        summary["contract_violation_count"] = len(contracts)
        summary["contract_violations"] = [
            {
                "type": c.get("type"),
                "endpoint": c.get("endpoint"),
                "service": c.get("service"),
                "evidence": c.get("evidence", {}),
                "description": c.get("description", "")[:120],
            }
            for c in contracts[:15]
        ]

    flows = full.get("flow_coverage", [])
    missing_flows = [f for f in flows if f.get("status") == "missing"]
    if missing_flows:
        summary["missing_flow_count"] = len(missing_flows)
        summary["missing_flows"] = [
            {
                "flow": f.get("flow"),
                "ep": f.get("ep"),
                "svc": f.get("svc"),
                "confidence": f.get("confidence"),
                "evidence": f.get("evidence", {}),
            }
            for f in missing_flows
        ]

    type_diagnostics = full.get("type_diagnostics", [])
    if type_diagnostics:
        summary["type_diagnostics"] = type_diagnostics[:20]

    return summary


def _log_review_delta(before: int, after: int) -> None:
    removed = before - after
    if removed > 0:
        logger.info("cross_reviewer removed=%d kept=%d", removed, after)
    elif removed < 0:
        logger.warning("cross_reviewer added=%d (unexpected) total=%d", -removed, after)
    else:
        logger.info("cross_reviewer kept all %d issues", after)
