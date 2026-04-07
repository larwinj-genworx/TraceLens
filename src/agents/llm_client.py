from __future__ import annotations

import asyncio
import itertools
import time
from typing import ClassVar

from langchain_core.messages import BaseMessage
from langchain_groq import ChatGroq

from src.config.settings import settings
from src.observability.logging.setup import get_logger

logger = get_logger(__name__)


class RateLimitedGroqClient:
    """Groq LLM client with round-robin API-key rotation and per-key
    rate-limit tracking.  Designed for the free tier where each key
    has a small TPM budget (12 000 tokens / min).

    Keys are rotated on every call, and a 429-hit key is quarantined
    for a cooldown window before being used again.
    """

    _lock: ClassVar[asyncio.Lock] = asyncio.Lock()
    _key_cycle: ClassVar[itertools.cycle | None] = None
    _key_available_at: ClassVar[dict[str, float]] = {}

    def __init__(
        self,
        model: str | None = None,
        temperature: float = 0.1,
    ) -> None:
        keys = settings.groq_api_keys
        if not keys:
            raise RuntimeError("No GROQ API keys configured (GROQ_API_KEYS / GROQ_API_KEY)")

        self.model_name = model or settings.groq_scanner_model
        self._temperature = temperature
        self._keys = keys

        if RateLimitedGroqClient._key_cycle is None:
            RateLimitedGroqClient._key_cycle = itertools.cycle(keys)
            RateLimitedGroqClient._key_available_at = {k: 0.0 for k in keys}
            logger.info("groq_key_pool initialized pool_size=%d", len(keys))

    def _build_llm(self, api_key: str) -> ChatGroq:
        return ChatGroq(
            model=self.model_name,
            api_key=api_key,
            temperature=self._temperature,
            max_retries=0,
            request_timeout=settings.groq_request_timeout_seconds,
        )

    async def invoke(self, messages: list[BaseMessage]) -> str:
        """Send a chat completion, rotating keys on 429s."""
        max_attempts = settings.groq_max_retries * len(self._keys)
        last_error: Exception | None = None

        for attempt in range(1, max_attempts + 1):
            api_key = await self._pick_key()
            key_tag = f"...{api_key[-6:]}"
            try:
                logger.info(
                    "groq_request model=%s key=%s attempt=%d/%d",
                    self.model_name,
                    key_tag,
                    attempt,
                    max_attempts,
                )
                llm = self._build_llm(api_key)
                response = await llm.ainvoke(messages)
                logger.info(
                    "groq_response model=%s key=%s tokens=%s",
                    self.model_name,
                    key_tag,
                    response.usage_metadata,
                )
                return response.content
            except Exception as exc:
                last_error = exc
                is_rate_limit = "429" in str(exc) or "rate" in str(exc).lower()

                if is_rate_limit:
                    cooldown = self._parse_retry_after(str(exc))
                    async with self._lock:
                        self._key_available_at[api_key] = time.monotonic() + cooldown
                    logger.warning(
                        "groq_rate_limited key=%s cooldown=%.1fs attempt=%d/%d",
                        key_tag,
                        cooldown,
                        attempt,
                        max_attempts,
                    )
                    await asyncio.sleep(min(cooldown, 5.0))
                else:
                    delay = settings.groq_retry_delay_seconds * (2 ** (attempt - 1))
                    delay = min(delay, 30.0)
                    logger.warning(
                        "groq_error key=%s delay=%.1fs attempt=%d/%d error=%s",
                        key_tag,
                        delay,
                        attempt,
                        max_attempts,
                        str(exc)[:200],
                    )
                    await asyncio.sleep(delay)

        raise last_error or RuntimeError("groq_request_exhausted_all_keys")

    async def _pick_key(self) -> str:
        """Return the next available key, waiting only if ALL keys are on cooldown."""
        async with self._lock:
            now = time.monotonic()

            for _ in range(len(self._keys)):
                key = next(self._key_cycle)
                ready_at = self._key_available_at.get(key, 0.0)
                if now >= ready_at:
                    return key

            earliest_key = min(self._key_available_at, key=self._key_available_at.get)
            wait = self._key_available_at[earliest_key] - now

        if wait > 0:
            logger.info("groq_all_keys_cooling waiting=%.1fs", wait)
            await asyncio.sleep(wait)

        async with self._lock:
            return next(self._key_cycle)

    @staticmethod
    def _parse_retry_after(error_text: str) -> float:
        """Extract the suggested wait from Groq's 429 message, e.g.
        'Please try again in 19.475s'."""
        import re
        match = re.search(r"try again in (\d+(?:\.\d+)?)s", error_text)
        if match:
            return float(match.group(1)) + 1.0
        return 20.0
