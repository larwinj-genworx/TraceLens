from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from src.agents.state import AgentState
from src.config.settings import settings
from src.constants.defaults import is_sensitive_field_name
from src.observability.logging.setup import get_logger
from src.schemas.internal import AnalysisContext, FlowStatus

logger = get_logger(__name__)

MAX_SNIPPET_LINES = settings.agent_code_snippet_lines

# Middleware name substrings that indicate authentication enforcement
_AUTH_MIDDLEWARE_KEYWORDS: frozenset[str] = frozenset(
    {"jwt", "auth", "bearer", "token", "session", "oauth"}
)


def prepare_evidence(state: AgentState) -> dict[str, Any]:
    """Deterministic node: serialise *AnalysisContext* into domain-chunked
    evidence dicts that each analyst agent can consume directly."""
    ctx: AnalysisContext = state["analysis_context"]
    logger.info("evidence_preparator started repos=%d", len(ctx.repos))

    # Build a lookup of authn_flow coverage per (service, endpoint) so that
    # _serialize_endpoints can annotate each endpoint with auth_covered.
    authn_covered_keys: set[tuple[str, str]] = set()
    for item in ctx.flow_coverage:
        if item.flow_id == "authn_flow" and item.status in (
            FlowStatus.COVERED, FlowStatus.AMBIGUOUS
        ):
            authn_covered_keys.add((item.service, item.endpoint))

    endpoints = _serialize_endpoints(ctx, authn_covered_keys)
    frontend_calls = _serialize_frontend_calls(ctx)
    graph_matches = _serialize_graph_matches(ctx)
    unmatched_calls = _serialize_unmatched(ctx)
    contract_violations = _serialize_contracts(ctx)
    flow_coverage = _serialize_flow_coverage(ctx)
    runtime_probes = _serialize_runtime(ctx)
    env_inference = _serialize_env(ctx)
    service_facts = _serialize_service_facts(ctx)
    type_diagnostics = _serialize_type_diagnostics(ctx)
    code_snippets = _collect_code_snippets(ctx) if settings.agent_include_code_snippets else {}
    client_storage_issues = _serialize_client_storage_issues(ctx)

    security_evidence = {
        "endpoints": endpoints,
        "service_facts": service_facts,
        "flow_coverage": flow_coverage,
        "runtime_probes": runtime_probes,
        "code_snippets": code_snippets,
        "type_diagnostics": type_diagnostics,
        "client_storage_issues": client_storage_issues,
    }
    integration_evidence = {
        "graph_matches": graph_matches,
        "unmatched_calls": unmatched_calls,
        "contract_violations": contract_violations,
        "runtime_probes": runtime_probes,
        "env_inference": env_inference,
        "endpoints": endpoints,
        "frontend_calls": frontend_calls,
        "service_facts": service_facts,
        "type_diagnostics": type_diagnostics,
    }
    quality_evidence = {
        "endpoints": endpoints,
        "frontend_calls": frontend_calls,
        "graph_matches": graph_matches,
        "code_snippets": code_snippets,
        "service_facts": service_facts,
        "flow_coverage": flow_coverage,
        "type_diagnostics": type_diagnostics,
    }
    full_evidence = {
        "endpoints": endpoints,
        "frontend_calls": frontend_calls,
        "graph_matches": graph_matches,
        "unmatched_calls": unmatched_calls,
        "contract_violations": contract_violations,
        "flow_coverage": flow_coverage,
        "runtime_probes": runtime_probes,
        "env_inference": env_inference,
        "service_facts": service_facts,
        "code_snippets": code_snippets,
        "type_diagnostics": type_diagnostics,
        "client_storage_issues": client_storage_issues,
    }

    evidence_package: dict[str, Any] = {
        "security": security_evidence,
        "integration": integration_evidence,
        "quality": quality_evidence,
        "full": full_evidence,
    }

    logger.info(
        "evidence_preparator done endpoints=%d calls=%d matches=%d contracts=%d flows=%d",
        len(endpoints),
        len(frontend_calls),
        len(graph_matches),
        len(contract_violations),
        len(flow_coverage),
    )
    return {"evidence_package": evidence_package}


def _serialize_endpoints(
    ctx: AnalysisContext,
    authn_covered_keys: set[tuple[str, str]] | None = None,
) -> list[dict[str, Any]]:
    covered = authn_covered_keys or set()
    out: list[dict[str, Any]] = []
    for static in ctx.static_results.values():
        for ep in static.backend_endpoints:
            sensitive_resp = [
                f.name for f in ep.response_fields if is_sensitive_field_name(f.name)
            ]
            entry: dict[str, Any] = {
                "svc": ep.service,
                "path": ep.path,
                "canonical_path": ep.canonical_path,
                "method": ep.method,
                "file": ep.file,
                "line": ep.line,
                "deps": ep.dependencies,
                "resp_fields": len(ep.response_fields),
                "route_intent": ep.route_intent,
                "auth_mode": ep.auth_mode,
                "ownership_mode": ep.ownership_mode,
            }
            # Explicit auth-coverage flag derived from the deterministic flow
            # analyzer.  When True, the security analyst must NOT flag
            # missing_auth regardless of the empty deps list.
            ep_key = (ep.service, f"{ep.method} {ep.path}")
            if ep_key in covered:
                entry["auth_covered"] = True
            if ep.is_websocket:
                entry["ws"] = True
            if ep.request_fields:
                entry["req_fields"] = [
                    {"n": f.name, "t": f.field_type, "r": f.required}
                    for f in ep.request_fields
                ]
            if ep.route_intent == "auth_entry":
                entry["token_response_expected"] = True
            if sensitive_resp:
                entry["sensitive"] = sensitive_resp
            if ep.redacted_response_fields:
                entry["redacted"] = ep.redacted_response_fields
            if ep.call_refs:
                entry["refs"] = ep.call_refs[:8]
            if ep.string_refs:
                entry["strs"] = ep.string_refs[:8]
            if not ep.has_try_except:
                entry["no_try"] = True
            out.append(entry)
    return out


def _serialize_frontend_calls(ctx: AnalysisContext) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for static in ctx.static_results.values():
        for call in static.frontend_calls:
            entry: dict[str, Any] = {
                "svc": call.service,
                "file": call.file,
                "line": call.line,
                "url": call.raw_url,
                "canonical_url": call.canonical_url,
                "canonical_path": call.canonical_path,
                "method": call.method,
                "payload_resolution": call.payload_resolution,
                "payload_fields": sorted(call.payload_fields.keys()),
            }
            if call.url_unresolved:
                entry["unresolved"] = True
            out.append(entry)
    return out


def _serialize_graph_matches(ctx: AnalysisContext) -> list[dict[str, Any]]:
    cv_endpoints: set[str] = {
        cv.get("endpoint", "") for cv in ctx.contract_issues
    }
    out: list[dict[str, Any]] = []
    for m in ctx.graph_result.matches:
        be_ref = f"{m.endpoint.method} {m.endpoint.path}"
        entry: dict[str, Any] = {
            "fe": m.frontend_repo,
            "be": m.backend_repo,
            "fe_file": m.call.file,
            "fe_method": m.call.method,
            "fe_url": m.call.raw_url,
            "fe_canonical_url": m.call.canonical_url,
            "fe_canonical_path": m.call.canonical_path,
            "payload_resolution": m.call.payload_resolution,
            "be_path": m.endpoint.path,
            "be_canonical_path": m.endpoint.canonical_path,
            "be_method": m.endpoint.method,
            "be_resp_fields": len(m.endpoint.response_fields),
            "contract_violation_exists": be_ref in cv_endpoints,
        }
        entry["fe_payload"] = list(m.call.payload_fields.keys())
        is_resolved = m.call.payload_resolution != "unresolved"
        if m.endpoint.request_fields and is_resolved:
            entry["be_req"] = [
                {"n": f.name, "r": f.required} for f in m.endpoint.request_fields
            ]
        out.append(entry)
    return out


def _serialize_unmatched(ctx: AnalysisContext) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for u in ctx.graph_result.unmatched_calls:
        if u.url_unresolved:
            continue
        out.append({
            "svc": u.service,
            "file": u.file,
            "url": u.raw_url,
            "canonical_url": u.canonical_url,
            "canonical_path": u.canonical_path,
            "method": u.method,
            "payload_resolution": u.payload_resolution,
        })
    return out


def _serialize_contracts(ctx: AnalysisContext) -> list[dict[str, Any]]:
    return [dict(c) for c in ctx.contract_issues]


def _serialize_flow_coverage(ctx: AnalysisContext) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for item in ctx.flow_coverage:
        if item.status.value == "not_applicable":
            continue
        entry: dict[str, Any] = {
            "flow": item.flow_id,
            "svc": item.service,
            "ep": item.endpoint,
            "status": item.status.value,
            "confidence": item.confidence,
        }
        if item.file:
            entry["file"] = item.file
        if item.evidence:
            entry["evidence"] = item.evidence
        out.append(entry)
    return out


def _serialize_runtime(ctx: AnalysisContext) -> list[dict[str, Any]]:
    if not ctx.runtime_result:
        return []
    out: list[dict[str, Any]] = []
    for probe in ctx.runtime_result.probes:
        entry: dict[str, Any] = {
            "method": probe.method,
            "url": probe.url,
            "status": probe.status_code,
        }
        if probe.error:
            entry["error"] = probe.error[:100]
        out.append(entry)
    return out


def _serialize_type_diagnostics(ctx: AnalysisContext) -> list[dict[str, Any]]:
    return [item.model_dump(mode="json") for item in ctx.type_diagnostics]


def _serialize_client_storage_issues(ctx: AnalysisContext) -> list[dict[str, Any]]:
    out: list[dict[str, Any]] = []
    for static in ctx.static_results.values():
        for issue in static.client_storage_issues:
            out.append(issue.model_dump(mode="json"))
    return out


def _serialize_service_facts(ctx: AnalysisContext) -> list[dict[str, Any]]:
    """Serialize per-service global facts (middleware, global deps) for LLM context."""
    out: list[dict[str, Any]] = []
    for service, static in ctx.static_results.items():
        facts = static.fastapi_facts
        if not facts.middleware_refs and not facts.global_dependencies and not facts.cors_config:
            continue
        entry: dict[str, Any] = {"svc": service}
        if facts.middleware_refs:
            entry["middleware"] = facts.middleware_refs
        if facts.global_dependencies:
            entry["global_deps"] = facts.global_dependencies

        # Classify auth strategy so the LLM does not have to guess.
        auth_mw = [
            ref for ref in facts.middleware_refs
            if any(kw in ref.lower() for kw in _AUTH_MIDDLEWARE_KEYWORDS)
        ]
        if auth_mw:
            entry["auth_strategy"] = "middleware"
            entry["auth_middleware"] = auth_mw
            # Surface public paths extracted from the catalog markers so the
            # LLM knows which routes are intentionally unprotected.
            public_paths = sorted({
                item.endpoint
                for item in ctx.flow_coverage
                if item.service == service
                and item.flow_id == "authn_flow"
                and item.status.value == "not_applicable"
            })
            if public_paths:
                entry["public_paths"] = public_paths
        elif facts.global_dependencies:
            entry["auth_strategy"] = "per_route"
        else:
            entry["auth_strategy"] = "per_route"

        if facts.cors_config:
            cors = facts.cors_config
            entry["cors_config"] = {
                "allow_origins": cors.allow_origins,
                "allow_credentials": cors.allow_credentials,
                "allow_methods": cors.allow_methods,
                "allow_headers": cors.allow_headers,
                "is_permissive": cors.is_permissive,
            }

        out.append(entry)
    return out


def _serialize_env(ctx: AnalysisContext) -> dict[str, Any]:
    return {
        "urls": ctx.env_result.service_base_urls,
    }


def _collect_code_snippets(ctx: AnalysisContext) -> dict[str, str]:
    """Read a few lines around each endpoint / call site for LLM context.

    Also collects full bodies of auth middleware classes and auth dependency
    functions so the security analyst has direct code evidence for global
    auth patterns.
    """
    snippets: dict[str, str] = {}
    workspace = settings.analysis_workspace

    for repo in ctx.repos:
        if repo.clone_error:
            continue
        repo_root = Path(repo.local_path)
        if not repo_root.exists():
            repo_root = workspace / repo.name
        static = ctx.static_results.get(repo.name)
        if not static:
            continue

        targets: list[tuple[str | None, int | None]] = []
        for ep in static.backend_endpoints:
            targets.append((ep.file, ep.line))
        for call in static.frontend_calls:
            targets.append((call.file, call.line))

        for file_rel, line in targets:
            if not file_rel or not line:
                continue
            key = f"{repo.name}:{file_rel}:{line}"
            if key in snippets:
                continue
            snippet = _read_snippet(repo_root, file_rel, line)
            if snippet:
                snippets[key] = snippet

        # Collect auth middleware class bodies so the LLM can see the
        # public_urls list and JWT validation logic directly.
        auth_mw_names = [
            ref for ref in static.fastapi_facts.middleware_refs
            if any(kw in ref.lower() for kw in _AUTH_MIDDLEWARE_KEYWORDS)
            and ref.lower() != "add_middleware"
        ]
        for mw_name in auth_mw_names:
            mw_snippet = _find_class_snippet(repo_root, mw_name)
            if mw_snippet:
                key = f"{repo.name}:middleware:{mw_name}"
                if key not in snippets:
                    snippets[key] = mw_snippet

        # Collect auth dependency function bodies (e.g. get_current_user).
        # Extract unique dependency function names from all endpoints.
        _AUTH_DEP_KEYWORDS: frozenset[str] = frozenset(
            {"get_current", "current_user", "verify_token", "validate_token",
             "authenticate", "require_auth", "auth_required", "get_user"}
        )
        collected_deps: set[str] = set()
        for ep in static.backend_endpoints:
            for dep in ep.dependencies:
                # dep format: "arg_name:function_name"
                func_name = dep.split(":")[-1].lower()
                if any(kw in func_name for kw in _AUTH_DEP_KEYWORDS):
                    raw_name = dep.split(":")[-1]
                    if raw_name not in collected_deps:
                        collected_deps.add(raw_name)
                        fn_snippet = _find_function_snippet(repo_root, raw_name)
                        if fn_snippet:
                            key = f"{repo.name}:dep:{raw_name}"
                            if key not in snippets:
                                snippets[key] = fn_snippet

    return snippets


def _find_class_snippet(repo_root: Path, class_name: str) -> str | None:
    """Search all .py files under repo_root for a class named class_name and
    return its full body (up to MAX_SNIPPET_LINES * 4 lines)."""
    class_re = re.compile(
        rf"^\s*class\s+{re.escape(class_name)}\s*[:(]", re.MULTILINE
    )
    max_lines = MAX_SNIPPET_LINES * 4
    for py_file in repo_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not class_re.search(content):
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if class_re.match(line) or (
                re.match(rf"\s*class\s+{re.escape(class_name)}\s*[:(]", line)
            ):
                end = min(len(lines), i + max_lines)
                numbered = [f"{j + 1:>4}| {lines[j]}" for j in range(i, end)]
                rel = str(py_file.relative_to(repo_root))
                header = f"# {rel} — class {class_name}"
                return header + "\n" + "\n".join(numbered)
    return None


def _find_function_snippet(repo_root: Path, func_name: str) -> str | None:
    """Search all .py files under repo_root for a def named func_name and
    return its body (up to MAX_SNIPPET_LINES * 2 lines)."""
    func_re = re.compile(
        rf"^\s*(?:async\s+)?def\s+{re.escape(func_name)}\s*\(", re.MULTILINE
    )
    max_lines = MAX_SNIPPET_LINES * 2
    for py_file in repo_root.rglob("*.py"):
        try:
            content = py_file.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue
        if not func_re.search(content):
            continue
        lines = content.splitlines()
        for i, line in enumerate(lines):
            if re.match(
                rf"\s*(?:async\s+)?def\s+{re.escape(func_name)}\s*\(", line
            ):
                end = min(len(lines), i + max_lines)
                numbered = [f"{j + 1:>4}| {lines[j]}" for j in range(i, end)]
                rel = str(py_file.relative_to(repo_root))
                header = f"# {rel} — def {func_name}"
                return header + "\n" + "\n".join(numbered)
    return None


def _read_snippet(repo_root: Path, file_rel: str, center_line: int) -> str | None:
    try:
        fp = repo_root / file_rel
        if not fp.exists() or not fp.is_file():
            return None
        lines = fp.read_text(errors="replace").splitlines()
        half = MAX_SNIPPET_LINES // 2
        start = max(0, center_line - 1 - half)
        end = min(len(lines), center_line + half)
        numbered = [
            f"{i + 1:>4}| {lines[i]}" for i in range(start, end)
        ]
        return "\n".join(numbered)
    except Exception:
        return None
