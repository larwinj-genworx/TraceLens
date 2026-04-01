from __future__ import annotations

import json
from typing import Any

import httpx

from src.config.settings import settings
from src.observability.logging.setup import get_logger
from src.schemas.issues import Issue

logger = get_logger(__name__)


class GroqClient:
    def __init__(self, api_key: str | None = None, model: str | None = None) -> None:
        self.api_key = api_key or settings.groq_api_key
        self.model = model or settings.groq_model
        self.endpoint = "https://api.groq.com/openai/v1/chat/completions"

    async def enhance_issues(self, issues: list[Issue]) -> list[Issue]:
        if not self.api_key or not issues:
            return issues

        summary_payload = [
            {
                "index": idx,
                "type": issue.type,
                "severity": issue.severity.value,
                "service": issue.service,
                "endpoint": issue.endpoint,
                "description": issue.description,
                "fix": issue.fix,
            }
            for idx, issue in enumerate(issues)
        ]

        messages = [
            {
                "role": "system",
                "content": (
                    "You improve issue explanations and fixes for engineering reports. "
                    "Do not change severities, types, services, or validation outcomes."
                ),
            },
            {
                "role": "user",
                "content": (
                    "Return strict JSON with shape {\"updates\": [{\"index\": int, \"description\": str, \"fix\": str}]} "
                    "for the following issues:\n"
                    + json.dumps(summary_payload, ensure_ascii=True)
                ),
            },
        ]

        body = {
            "model": self.model,
            "temperature": 0.1,
            "messages": messages,
            "max_tokens": 1200,
            "response_format": {"type": "json_object"},
        }

        headers = {
            "Authorization": f"Bearer {self.api_key}",
            "Content-Type": "application/json",
        }

        try:
            async with httpx.AsyncClient(timeout=30) as client:
                response = await client.post(self.endpoint, headers=headers, json=body)
            if response.status_code >= 400:
                logger.warning(
                    "groq_enhancement_failed status=%s body=%s",
                    response.status_code,
                    response.text[:400],
                    extra={"request_id": "-"},
                )
                return issues

            payload = response.json()
            content = payload["choices"][0]["message"]["content"]
            updates = self._extract_updates(content)
            return self._apply_updates(issues, updates)
        except Exception:  # noqa: BLE001
            logger.exception("groq_enhancement_exception", extra={"request_id": "-"})
            return issues

    def _extract_updates(self, content: str) -> list[dict[str, Any]]:
        try:
            parsed = json.loads(content)
        except json.JSONDecodeError:
            start = content.find("{")
            end = content.rfind("}")
            if start == -1 or end == -1:
                return []
            try:
                parsed = json.loads(content[start : end + 1])
            except json.JSONDecodeError:
                return []

        updates = parsed.get("updates", [])
        if not isinstance(updates, list):
            return []
        return [item for item in updates if isinstance(item, dict)]

    def _apply_updates(self, issues: list[Issue], updates: list[dict[str, Any]]) -> list[Issue]:
        updated_issues = list(issues)
        for item in updates:
            index = item.get("index")
            if not isinstance(index, int) or index < 0 or index >= len(updated_issues):
                continue
            issue = updated_issues[index]
            description = item.get("description")
            fix = item.get("fix")
            updated_issues[index] = issue.model_copy(
                update={
                    "description": description if isinstance(description, str) and description.strip() else issue.description,
                    "fix": fix if isinstance(fix, str) and fix.strip() else issue.fix,
                }
            )
        return updated_issues
