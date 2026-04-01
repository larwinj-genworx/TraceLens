from __future__ import annotations

import logging
import sys

from src.observability.tracing.context import get_request_id


def configure_logging(level: int = logging.INFO) -> None:
    if logging.getLogger().handlers:
        return

    formatter = logging.Formatter(
        "%(asctime)s | %(levelname)s | %(name)s | req_id=%(request_id)s | %(message)s",
        "%Y-%m-%d %H:%M:%S",
    )

    handler = logging.StreamHandler(sys.stdout)
    handler.setFormatter(formatter)
    handler.addFilter(RequestContextFilter())

    root = logging.getLogger()
    root.setLevel(level)
    root.addHandler(handler)


class RequestContextFilter(logging.Filter):
    def filter(self, record: logging.LogRecord) -> bool:
        if not hasattr(record, "request_id"):
            record.request_id = get_request_id()
        return True


def get_logger(name: str) -> logging.Logger:
    logger = logging.getLogger(name)
    has_filter = any(isinstance(current_filter, RequestContextFilter) for current_filter in logger.filters)
    if not has_filter:
        logger.addFilter(RequestContextFilter())
    return logger
