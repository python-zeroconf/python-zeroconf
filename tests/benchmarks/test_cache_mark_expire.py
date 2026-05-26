"""Benchmarks for DNSCache.async_mark_unique_records_older_than_1s_to_expire.

Covers the RFC 6762 §10.2 paragraph 2 path that marks superseded unique
records to expire in 1s. Today it mutates cached records in place via
``DNSRecord._set_created_ttl`` (see ``_cache.py`` line ~345). These
benchmarks pin the cost of the current path so a copy-instead-of-mutate
follow-up (issue #1780) has a baseline to compare against.
"""

from __future__ import annotations

from pytest_codspeed import BenchmarkFixture

from zeroconf import DNSAddress, DNSCache, DNSPointer, current_time_millis
from zeroconf.const import _CLASS_IN, _CLASS_UNIQUE, _TYPE_A, _TYPE_PTR

_UNIQUE_CLASS = _CLASS_IN | _CLASS_UNIQUE


def _ipv4_bytes(i: int) -> bytes:
    return bytes(((i >> 24) & 0xFF, (i >> 16) & 0xFF, (i >> 8) & 0xFF, i & 0xFF))


def test_mark_to_expire_1000_records_all_stale(benchmark: BenchmarkFixture) -> None:
    """Worst-case mark-to-expire: every cached record needs mutation.

    1000 unique A records, all created > 1s ago, none in the new answer
    set — every iteration hits the ``_async_set_created_ttl`` path.
    """
    now = current_time_millis()
    name = "stale.local."
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
    unique_types = {(name, _TYPE_A, _UNIQUE_CLASS)}
    # An unrelated answer keeps every cached record in the "must expire"
    # branch (no membership hit short-circuits the mutation).
    answers = [DNSAddress(name, _TYPE_A, _UNIQUE_CLASS, 120, _ipv4_bytes(0xDEAD_BEEF))]

    @benchmark
    def _mark() -> None:
        cache.async_mark_unique_records_older_than_1s_to_expire(unique_types, answers, now)


def test_mark_to_expire_1000_records_none_stale(benchmark: BenchmarkFixture) -> None:
    """Same shape, but every record is fresh (created < 1s ago).

    Measures the scan + age-check overhead without paying any
    ``_async_set_created_ttl`` cost. The delta to the all-stale case is
    the mutation+re-add tax we'd avoid by switching to copy-on-expire.
    """
    now = current_time_millis()
    name = "fresh.local."
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
    unique_types = {(name, _TYPE_A, _UNIQUE_CLASS)}
    answers = [DNSAddress(name, _TYPE_A, _UNIQUE_CLASS, 120, _ipv4_bytes(0xDEAD_BEEF))]

    @benchmark
    def _mark() -> None:
        cache.async_mark_unique_records_older_than_1s_to_expire(unique_types, answers, now)


def test_mark_to_expire_many_unique_types(benchmark: BenchmarkFixture) -> None:
    """Many distinct (name, type, class) triplets, one stale record each.

    Mirrors a burst response that supersedes 100 different unique RRsets
    in one packet — the outer loop dominates, but each inner iteration
    still triggers in-place mutation.
    """
    now = current_time_millis()
    cache = DNSCache()
    unique_types: set[tuple[str, int, int]] = set()
    for i in range(100):
        name = f"svc{i}.local."
        cache.async_add_records(
            [
                DNSPointer(
                    name,
                    _TYPE_PTR,
                    _UNIQUE_CLASS,
                    120,
                    f"target{i}.local.",
                    created=now - 5_000,
                )
            ]
        )
        unique_types.add((name, _TYPE_PTR, _UNIQUE_CLASS))
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

    @benchmark
    def _mark() -> None:
        cache.async_mark_unique_records_older_than_1s_to_expire(unique_types, answers, now)
