"""Benchmark for the DNSCache record-count bound + overflow eviction."""

from __future__ import annotations

from collections.abc import Iterator
from itertools import count

from pytest_codspeed import BenchmarkFixture

from zeroconf import DNSAddress, DNSCache, current_time_millis
from zeroconf.const import _CLASS_IN, _MAX_CACHE_RECORDS, _TYPE_A


def _make_records(count_: int, now: float, prefix: str = "bench") -> list[DNSAddress]:
    return [
        DNSAddress(
            f"{prefix}-{i}.local.",
            _TYPE_A,
            _CLASS_IN,
            120,
            bytes(((i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF)),
            created=now + i,
        )
        for i in range(count_)
    ]


def _unbounded_records(now: float, prefix: str = "evict") -> Iterator[DNSAddress]:
    """Unbounded generator of unique-name DNSAddress records."""
    for i in count():
        yield DNSAddress(
            f"{prefix}-{i}.local.",
            _TYPE_A,
            _CLASS_IN,
            120,
            bytes(((i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF)),
            created=now + i,
        )


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
    pulls one fresh unique record from an unbounded generator, keeping the
    cache permanently at the cap. The generator avoids the iteration-count
    cap that a pre-built pool would impose for very fast operations.
    """
    now = current_time_millis()
    cache = DNSCache()
    cache.async_add_records(_make_records(_MAX_CACHE_RECORDS, now, prefix="fill"))
    pool = _unbounded_records(now + _MAX_CACHE_RECORDS)

    @benchmark
    def _evict_one() -> None:
        cache.async_add_records([next(pool)])
