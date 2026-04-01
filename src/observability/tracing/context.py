from __future__ import annotations

from contextvars import ContextVar


request_id_ctx: ContextVar[str] = ContextVar("request_id", default="-")


def get_request_id() -> str:
    return request_id_ctx.get()
