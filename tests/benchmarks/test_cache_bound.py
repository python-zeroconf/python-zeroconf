"""Benchmark for the DNSCache record-count bound + overflow eviction."""

from __future__ import annotations

from pytest_codspeed import BenchmarkFixture

from zeroconf import DNSAddress, DNSCache, current_time_millis
from zeroconf.const import _CLASS_IN, _MAX_CACHE_RECORDS, _TYPE_A


def _make_records(count: int, now: float) -> list[DNSAddress]:
    return [
        DNSAddress(
            f"bench-{i}.local.",
            _TYPE_A,
            _CLASS_IN,
            120,
            bytes((i & 0xFF, (i >> 8) & 0xFF, 0, 1)),
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
    """Steady-state add at the cap: every new record forces one eviction."""
    now = current_time_millis()
    overflow_records = _make_records(_MAX_CACHE_RECORDS + 1000, now)

    @benchmark
    def _flood() -> None:
        cache = DNSCache()
        cache.async_add_records(overflow_records)
