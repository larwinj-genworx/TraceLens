from __future__ import annotations

from collections import defaultdict
from threading import Lock


class InMemoryMetrics:
    def __init__(self) -> None:
        self._counters: dict[str, int] = defaultdict(int)
        self._timings: dict[str, list[float]] = defaultdict(list)
        self._lock = Lock()

    def inc(self, name: str, amount: int = 1) -> None:
        with self._lock:
            self._counters[name] += amount

    def observe(self, name: str, value: float) -> None:
        with self._lock:
            self._timings[name].append(value)

    def snapshot(self) -> dict[str, dict[str, float | int]]:
        with self._lock:
            timing_summary: dict[str, dict[str, float | int]] = {}
            for key, values in self._timings.items():
                if not values:
                    continue
                timing_summary[key] = {
                    "count": len(values),
                    "avg": sum(values) / len(values),
                    "max": max(values),
                }
            return {
                "counters": dict(self._counters),
                "timings": timing_summary,
            }


metrics_registry = InMemoryMetrics()
