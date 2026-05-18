"""Benchmark for _logger._mark_seen."""

from __future__ import annotations

from pytest_codspeed import BenchmarkFixture

from zeroconf._logger import _MAX_SEEN_LOGS, _mark_seen


def test_mark_seen_hit(benchmark: BenchmarkFixture) -> None:
    """Benchmark the cache-hit path (same key repeated)."""
    seen: dict[str, None] = {"warm": None}

    @benchmark
    def _hit() -> None:
        for _ in range(1000):
            _mark_seen(seen, "warm")


def test_mark_seen_fill(benchmark: BenchmarkFixture) -> None:
    """Benchmark filling from empty up to the cap (no evictions)."""
    keys = [f"key-{i}" for i in range(_MAX_SEEN_LOGS)]

    @benchmark
    def _fill() -> None:
        seen: dict[str, None] = {}
        for k in keys:
            _mark_seen(seen, k)


def test_mark_seen_churn(benchmark: BenchmarkFixture) -> None:
    """Benchmark sustained eviction (every call past the cap drops oldest)."""
    keys = [f"churn-{i}" for i in range(_MAX_SEEN_LOGS * 4)]

    @benchmark
    def _churn() -> None:
        seen: dict[str, None] = {}
        for k in keys:
            _mark_seen(seen, k)
