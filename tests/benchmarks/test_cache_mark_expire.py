"""Benchmarks for DNSCache.async_mark_unique_records_older_than_1s_to_expire.

Covers the RFC 6762 §10.2 paragraph 2 path. ``_async_set_created_ttl``
mutates cached records in place, so a repeated-iteration benchmark
would only measure work on the first call. Each test uses
``benchmark.pedantic`` with a per-round ``setup`` that rebuilds the
stale cache; the ``async_add_records`` cost stays outside the timed
window.
"""

from __future__ import annotations

from typing import Any

from pytest_codspeed import BenchmarkFixture

from zeroconf import DNSAddress, DNSCache, DNSPointer, current_time_millis
from zeroconf.const import _CLASS_IN, _CLASS_UNIQUE, _TYPE_A, _TYPE_PTR

_UNIQUE_CLASS = _CLASS_IN | _CLASS_UNIQUE


def _ipv4_bytes(i: int) -> bytes:
    return bytes(((i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF))


def test_mark_to_expire_1000_records_all_stale(benchmark: BenchmarkFixture) -> None:
    """Worst-case mark-to-expire: 1000 stale unique A records, all mutated."""
    now = current_time_millis()
    name = "stale.local."
    unique_types = {(name, _TYPE_A, _UNIQUE_CLASS)}
    # Unrelated answer keeps every cached record in the "must expire"
    # branch (no membership hit short-circuits the mutation).
    answers = [DNSAddress(name, _TYPE_A, _UNIQUE_CLASS, 120, _ipv4_bytes(0xDEAD_BEEF))]

    def _setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        cache = DNSCache()
        cache.async_add_records(
            DNSAddress(
                name,
                _TYPE_A,
                _UNIQUE_CLASS,
                120,
                _ipv4_bytes(i),
                created=now - 5_000,
            )
            for i in range(1000)
        )
        return (cache,), {}

    def _mark(cache: DNSCache) -> None:
        cache.async_mark_unique_records_older_than_1s_to_expire(unique_types, answers, now)

    benchmark.pedantic(_mark, setup=_setup)


def test_mark_to_expire_1000_records_none_stale(benchmark: BenchmarkFixture) -> None:
    """Scan-only path: 1000 fresh records, no mutation."""
    now = current_time_millis()
    name = "fresh.local."
    unique_types = {(name, _TYPE_A, _UNIQUE_CLASS)}
    answers = [DNSAddress(name, _TYPE_A, _UNIQUE_CLASS, 120, _ipv4_bytes(0xDEAD_BEEF))]

    def _setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        cache = DNSCache()
        cache.async_add_records(
            DNSAddress(
                name,
                _TYPE_A,
                _UNIQUE_CLASS,
                120,
                _ipv4_bytes(i),
                created=now,
            )
            for i in range(1000)
        )
        return (cache,), {}

    def _mark(cache: DNSCache) -> None:
        cache.async_mark_unique_records_older_than_1s_to_expire(unique_types, answers, now)

    benchmark.pedantic(_mark, setup=_setup)


def test_mark_to_expire_many_unique_types(benchmark: BenchmarkFixture) -> None:
    """100 distinct (name, type, class) triplets, one stale record each."""
    now = current_time_millis()
    unique_types: set[tuple[str, int, int]] = {
        (f"svc{i}.local.", _TYPE_PTR, _UNIQUE_CLASS) for i in range(100)
    }
    # New answers reference a different alias, so the cached entries are
    # not equal to anything in ``answers_rrset`` and must be expired.
    answers = [
        DNSPointer(
            f"svc{i}.local.",
            _TYPE_PTR,
            _UNIQUE_CLASS,
            120,
            f"new-target{i}.local.",
        )
        for i in range(100)
    ]

    def _setup() -> tuple[tuple[Any, ...], dict[str, Any]]:
        cache = DNSCache()
        for i in range(100):
            cache.async_add_records(
                [
                    DNSPointer(
                        f"svc{i}.local.",
                        _TYPE_PTR,
                        _UNIQUE_CLASS,
                        120,
                        f"target{i}.local.",
                        created=now - 5_000,
                    )
                ]
            )
        return (cache,), {}

    def _mark(cache: DNSCache) -> None:
        cache.async_mark_unique_records_older_than_1s_to_expire(unique_types, answers, now)

    benchmark.pedantic(_mark, setup=_setup)
