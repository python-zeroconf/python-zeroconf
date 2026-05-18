"""Benchmark for the DNSCache record-count bound + overflow eviction."""

from __future__ import annotations

from pytest_codspeed import BenchmarkFixture

from zeroconf import DNSAddress, DNSCache, current_time_millis
from zeroconf.const import _CLASS_IN, _MAX_CACHE_RECORDS, _TYPE_A


def _make_records(count: int, now: float, prefix: str = "bench") -> list[DNSAddress]:
    return [
        DNSAddress(
            f"{prefix}-{i}.local.",
            _TYPE_A,
            _CLASS_IN,
            120,
            bytes(((i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF)),
            created=now + i,
        )
        for i in range(count)
    ]


def test_cache_add_below_cap(benchmark: BenchmarkFixture) -> None:
    """Adding records while the cache is well below the cap (no eviction)."""
    now = current_time_millis()
    records = _make_records(1000, now)

    @benchmark
    def _add() -> None:
        cache = DNSCache()
        cache.async_add_records(records)


def test_cache_add_at_cap_evicts(benchmark: BenchmarkFixture) -> None:
    """Steady-state add at the cap: every measured insert forces one eviction.

    Pre-fills the cache to ``_MAX_CACHE_RECORDS`` outside the timed body so
    only the eviction-path adds are measured. Each benchmark iteration
    consumes one fresh unique record from a pre-built pool, keeping the
    cache permanently at the cap and the work per iteration to a single
    ``_async_add`` + ``_async_evict_oldest`` cycle.
    """
    now = current_time_millis()
    cache = DNSCache()
    cache.async_add_records(_make_records(_MAX_CACHE_RECORDS, now, prefix="fill"))
    # Large pool so the iterator outlives any reasonable codspeed run count.
    pool = iter(_make_records(100_000, now + _MAX_CACHE_RECORDS, prefix="evict"))

    @benchmark
    def _evict_one() -> None:
        cache.async_add_records([next(pool)])
