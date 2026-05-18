"""Unit tests for zeroconf._cache."""

from __future__ import annotations

import logging
import unittest.mock
from heapq import heapify, heappop

import pytest

import zeroconf as r
from zeroconf import const

log = logging.getLogger("zeroconf")
original_logging_level = logging.NOTSET


def setup_module():
    global original_logging_level
    original_logging_level = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    if original_logging_level != logging.NOTSET:
        log.setLevel(original_logging_level)


class TestDNSCache(unittest.TestCase):
    def test_order(self):
        record1 = r.DNSAddress("a", const._TYPE_SOA, const._CLASS_IN, 1, b"a")
        record2 = r.DNSAddress("a", const._TYPE_SOA, const._CLASS_IN, 1, b"b")
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        entry = r.DNSEntry("a", const._TYPE_SOA, const._CLASS_IN)
        cached_record = cache.get(entry)
        assert cached_record == record2

    def test_adding_same_record_to_cache_different_ttls_with_get(self):
        """We should always get back the last entry we added if there are different TTLs.

        This ensures we only have one source of truth for TTLs as a record cannot
        be both expired and not expired.
        """
        record1 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a")
        record2 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 10, b"a")
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        entry = r.DNSEntry(record2.name, const._TYPE_A, const._CLASS_IN)
        cached_record = cache.get(entry)
        assert cached_record == record2

    def test_adding_same_record_to_cache_different_ttls_with_get_all(self):
        """Verify we only get one record back.

        The last record added should replace the previous since two
        records with different ttls are __eq__. This ensures we
        only have one source of truth for TTLs as a record cannot
        be both expired and not expired.
        """
        record1 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a")
        record2 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 10, b"a")
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        cached_records = cache.get_all_by_details("a", const._TYPE_A, const._CLASS_IN)
        assert cached_records == [record2]

    def test_cache_empty_does_not_leak_memory_by_leaving_empty_list(self):
        record1 = r.DNSAddress("a", const._TYPE_SOA, const._CLASS_IN, 1, b"a")
        record2 = r.DNSAddress("a", const._TYPE_SOA, const._CLASS_IN, 1, b"b")
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        assert "a" in cache.cache
        cache.async_remove_records([record1, record2])
        assert "a" not in cache.cache

    def test_cache_empty_multiple_calls(self):
        record1 = r.DNSAddress("a", const._TYPE_SOA, const._CLASS_IN, 1, b"a")
        record2 = r.DNSAddress("a", const._TYPE_SOA, const._CLASS_IN, 1, b"b")
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        assert "a" in cache.cache
        cache.async_remove_records([record1, record2])
        assert "a" not in cache.cache


class TestDNSAsyncCacheAPI(unittest.TestCase):
    def test_async_get_unique(self):
        record1 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a")
        record2 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"b")
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        assert cache.async_get_unique(record1) == record1
        assert cache.async_get_unique(record2) == record2

    def test_async_all_by_details(self):
        record1 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a")
        record2 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"b")
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        assert set(cache.async_all_by_details("a", const._TYPE_A, const._CLASS_IN)) == {
            record1,
            record2,
        }

    def test_async_entries_with_server(self):
        record1 = r.DNSService(
            "irrelevant",
            const._TYPE_SRV,
            const._CLASS_IN,
            const._DNS_HOST_TTL,
            0,
            0,
            85,
            "ab",
        )
        record2 = r.DNSService(
            "irrelevant",
            const._TYPE_SRV,
            const._CLASS_IN,
            const._DNS_HOST_TTL,
            0,
            0,
            80,
            "ab",
        )
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        assert set(cache.async_entries_with_server("ab")) == {record1, record2}
        assert set(cache.async_entries_with_server("AB")) == {record1, record2}

    def test_async_entries_with_name(self):
        record1 = r.DNSService(
            "irrelevant",
            const._TYPE_SRV,
            const._CLASS_IN,
            const._DNS_HOST_TTL,
            0,
            0,
            85,
            "ab",
        )
        record2 = r.DNSService(
            "irrelevant",
            const._TYPE_SRV,
            const._CLASS_IN,
            const._DNS_HOST_TTL,
            0,
            0,
            80,
            "ab",
        )
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        assert set(cache.async_entries_with_name("irrelevant")) == {record1, record2}
        assert set(cache.async_entries_with_name("Irrelevant")) == {record1, record2}


# These functions have been seen in other projects so
# we try to maintain a stable API for all the threadsafe getters
class TestDNSCacheAPI(unittest.TestCase):
    def test_get(self):
        record1 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a")
        record2 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"b")
        record3 = r.DNSAddress("a", const._TYPE_AAAA, const._CLASS_IN, 1, b"ipv6")
        cache = r.DNSCache()
        cache.async_add_records([record1, record2, record3])
        assert cache.get(record1) == record1
        assert cache.get(record2) == record2
        assert cache.get(r.DNSEntry("a", const._TYPE_A, const._CLASS_IN)) == record2
        assert cache.get(r.DNSEntry("a", const._TYPE_AAAA, const._CLASS_IN)) == record3
        assert cache.get(r.DNSEntry("notthere", const._TYPE_A, const._CLASS_IN)) is None

    def test_get_by_details(self):
        record1 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a")
        record2 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"b")
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        assert cache.get_by_details("a", const._TYPE_A, const._CLASS_IN) == record2

    def test_get_all_by_details(self):
        record1 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a")
        record2 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"b")
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        assert set(cache.get_all_by_details("a", const._TYPE_A, const._CLASS_IN)) == {
            record1,
            record2,
        }

    def test_entries_with_server(self):
        record1 = r.DNSService(
            "irrelevant",
            const._TYPE_SRV,
            const._CLASS_IN,
            const._DNS_HOST_TTL,
            0,
            0,
            85,
            "ab",
        )
        record2 = r.DNSService(
            "irrelevant",
            const._TYPE_SRV,
            const._CLASS_IN,
            const._DNS_HOST_TTL,
            0,
            0,
            80,
            "ab",
        )
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        assert set(cache.entries_with_server("ab")) == {record1, record2}
        assert set(cache.entries_with_server("AB")) == {record1, record2}

    def test_entries_with_name(self):
        record1 = r.DNSService(
            "irrelevant",
            const._TYPE_SRV,
            const._CLASS_IN,
            const._DNS_HOST_TTL,
            0,
            0,
            85,
            "ab",
        )
        record2 = r.DNSService(
            "irrelevant",
            const._TYPE_SRV,
            const._CLASS_IN,
            const._DNS_HOST_TTL,
            0,
            0,
            80,
            "ab",
        )
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        assert set(cache.entries_with_name("irrelevant")) == {record1, record2}
        assert set(cache.entries_with_name("Irrelevant")) == {record1, record2}

    def test_current_entry_with_name_and_alias(self):
        record1 = r.DNSPointer(
            "irrelevant",
            const._TYPE_PTR,
            const._CLASS_IN,
            const._DNS_OTHER_TTL,
            "x.irrelevant",
        )
        record2 = r.DNSPointer(
            "irrelevant",
            const._TYPE_PTR,
            const._CLASS_IN,
            const._DNS_OTHER_TTL,
            "y.irrelevant",
        )
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        assert cache.current_entry_with_name_and_alias("irrelevant", "x.irrelevant") == record1

    def test_name(self):
        record1 = r.DNSService(
            "irrelevant",
            const._TYPE_SRV,
            const._CLASS_IN,
            const._DNS_HOST_TTL,
            0,
            0,
            85,
            "ab",
        )
        record2 = r.DNSService(
            "irrelevant",
            const._TYPE_SRV,
            const._CLASS_IN,
            const._DNS_HOST_TTL,
            0,
            0,
            80,
            "ab",
        )
        cache = r.DNSCache()
        cache.async_add_records([record1, record2])
        assert cache.names() == ["irrelevant"]


def test_async_entries_with_name_returns_newest_record():
    cache = r.DNSCache()
    record1 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a", created=1.0)
    record2 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a", created=2.0)
    cache.async_add_records([record1])
    cache.async_add_records([record2])
    assert next(iter(cache.async_entries_with_name("a"))) is record2


def test_async_entries_with_server_returns_newest_record():
    cache = r.DNSCache()
    record1 = r.DNSService("a", const._TYPE_SRV, const._CLASS_IN, 1, 1, 1, 1, "a", created=1.0)
    record2 = r.DNSService("a", const._TYPE_SRV, const._CLASS_IN, 1, 1, 1, 1, "a", created=2.0)
    cache.async_add_records([record1])
    cache.async_add_records([record2])
    assert next(iter(cache.async_entries_with_server("a"))) is record2


def test_async_get_returns_newest_record():
    cache = r.DNSCache()
    record1 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a", created=1.0)
    record2 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a", created=2.0)
    cache.async_add_records([record1])
    cache.async_add_records([record2])
    assert cache.get(record2) is record2


def test_async_get_returns_newest_nsec_record():
    cache = r.DNSCache()
    record1 = r.DNSNsec("a", const._TYPE_NSEC, const._CLASS_IN, 1, "a", [], created=1.0)
    record2 = r.DNSNsec("a", const._TYPE_NSEC, const._CLASS_IN, 1, "a", [], created=2.0)
    cache.async_add_records([record1])
    cache.async_add_records([record2])
    assert cache.get(record2) is record2


def test_get_by_details_returns_newest_record():
    cache = r.DNSCache()
    record1 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a", created=1.0)
    record2 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a", created=2.0)
    cache.async_add_records([record1])
    cache.async_add_records([record2])
    assert cache.get_by_details("a", const._TYPE_A, const._CLASS_IN) is record2


def test_get_all_by_details_returns_newest_record():
    cache = r.DNSCache()
    record1 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a", created=1.0)
    record2 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a", created=2.0)
    cache.async_add_records([record1])
    cache.async_add_records([record2])
    records = cache.get_all_by_details("a", const._TYPE_A, const._CLASS_IN)
    assert len(records) == 1
    assert records[0] is record2


def test_async_get_all_by_details_returns_newest_record():
    cache = r.DNSCache()
    record1 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a", created=1.0)
    record2 = r.DNSAddress("a", const._TYPE_A, const._CLASS_IN, 1, b"a", created=2.0)
    cache.async_add_records([record1])
    cache.async_add_records([record2])
    records = cache.async_all_by_details("a", const._TYPE_A, const._CLASS_IN)
    assert len(records) == 1
    assert records[0] is record2


def test_async_get_unique_returns_newest_record():
    cache = r.DNSCache()
    record1 = r.DNSPointer("a", const._TYPE_PTR, const._CLASS_IN, 1, "a", created=1.0)
    record2 = r.DNSPointer("a", const._TYPE_PTR, const._CLASS_IN, 1, "a", created=2.0)
    cache.async_add_records([record1])
    cache.async_add_records([record2])
    record = cache.async_get_unique(record1)
    assert record is record2
    record = cache.async_get_unique(record2)
    assert record is record2


@pytest.mark.asyncio
async def test_cache_heap_cleanup() -> None:
    """Test that the heap gets cleaned up when there are many old expirations."""
    cache = r.DNSCache()
    # The heap should not be cleaned up when there are less than 100 expiration changes
    min_records_to_cleanup = 100
    now = r.current_time_millis()
    name = "heap.local."
    ttl_seconds = 100
    ttl_millis = ttl_seconds * 1000

    for i in range(min_records_to_cleanup):
        record = r.DNSAddress(name, const._TYPE_A, const._CLASS_IN, ttl_seconds, b"1", created=now + i)
        cache.async_add_records([record])

    assert len(cache._expire_heap) == min_records_to_cleanup
    assert len(cache.async_entries_with_name(name)) == 1

    # Now that we reached the minimum number of cookies to cleanup,
    # add one more cookie to trigger the cleanup
    record = r.DNSAddress(
        name, const._TYPE_A, const._CLASS_IN, ttl_seconds, b"1", created=now + min_records_to_cleanup
    )
    expected_expire_time = record.created + ttl_millis
    cache.async_add_records([record])
    assert len(cache.async_entries_with_name(name)) == 1
    entry = next(iter(cache.async_entries_with_name(name)))
    assert (entry.created + ttl_millis) == expected_expire_time
    assert entry is record

    # Verify that the heap has been cleaned up
    assert len(cache.async_entries_with_name(name)) == 1
    cache.async_expire(now)

    heap_copy = cache._expire_heap.copy()
    heapify(heap_copy)
    # Ensure heap order is maintained
    assert cache._expire_heap == heap_copy

    # The heap should have been cleaned up
    assert len(cache._expire_heap) == 1
    assert len(cache.async_entries_with_name(name)) == 1

    entry = next(iter(cache.async_entries_with_name(name)))
    assert entry is record

    assert (entry.created + ttl_millis) == expected_expire_time

    cache.async_expire(expected_expire_time)
    assert not cache.async_entries_with_name(name), cache._expire_heap


@pytest.mark.asyncio
async def test_cache_heap_multi_name_cleanup() -> None:
    """Test cleanup with multiple names."""
    cache = r.DNSCache()
    # The heap should not be cleaned up when there are less than 100 expiration changes
    min_records_to_cleanup = 100
    now = r.current_time_millis()
    name = "heap.local."
    name2 = "heap2.local."
    ttl_seconds = 100
    ttl_millis = ttl_seconds * 1000

    for i in range(min_records_to_cleanup):
        record = r.DNSAddress(name, const._TYPE_A, const._CLASS_IN, ttl_seconds, b"1", created=now + i)
        cache.async_add_records([record])
    expected_expire_time = record.created + ttl_millis

    for i in range(5):
        record = r.DNSAddress(
            name2, const._TYPE_A, const._CLASS_IN, ttl_seconds, bytes((i,)), created=now + i
        )
        cache.async_add_records([record])

    # ``_async_add`` rebuilds ``_expire_heap`` proactively when stale entries
    # dominate (heap > 2x expirations), so the heap is already capped at
    # ~one entry per unique record long before ``async_expire`` is called.
    assert len(cache.async_entries_with_name(name)) == 1
    assert len(cache.async_entries_with_name(name2)) == 5

    cache.async_expire(now)
    # The heap and expirations should have been cleaned up
    assert len(cache._expire_heap) == 1 + 5
    assert len(cache._expirations) == 1 + 5

    cache.async_expire(expected_expire_time)
    assert not cache.async_entries_with_name(name), cache._expire_heap


@pytest.mark.asyncio
async def test_cache_heap_pops_order() -> None:
    """Test cache heap is popped in order."""
    cache = r.DNSCache()
    # The heap should not be cleaned up when there are less than 100 expiration changes
    min_records_to_cleanup = 100
    now = r.current_time_millis()
    name = "heap.local."
    name2 = "heap2.local."
    ttl_seconds = 100

    for i in range(min_records_to_cleanup):
        record = r.DNSAddress(name, const._TYPE_A, const._CLASS_IN, ttl_seconds, b"1", created=now + i)
        cache.async_add_records([record])

    for i in range(5):
        record = r.DNSAddress(
            name2, const._TYPE_A, const._CLASS_IN, ttl_seconds, bytes((i,)), created=now + i
        )
        cache.async_add_records([record])

    # ``_async_add`` proactively rebuilds the heap when stale entries dominate,
    # so the heap holds only one entry per unique record by this point.
    assert len(cache.async_entries_with_name(name)) == 1
    assert len(cache.async_entries_with_name(name2)) == 5

    start_ts = 0.0
    while cache._expire_heap:
        ts, _ = heappop(cache._expire_heap)
        assert ts >= start_ts
        start_ts = ts


def _addr(name: str, idx: int, *, ttl: int = 120, created: float | None = None) -> r.DNSAddress:
    """Build a DNSAddress with idx-derived payload for the bound/eviction tests."""
    return r.DNSAddress(
        name,
        const._TYPE_A,
        const._CLASS_IN,
        ttl,
        bytes((idx & 0xFF, (idx >> 8) & 0xFF, 0, 1)),
        created=r.current_time_millis() if created is None else created,
    )


def test_cache_size_is_bounded() -> None:
    """A flood of unique-name records is capped at ``_MAX_CACHE_RECORDS``."""
    cache = r.DNSCache()
    now = r.current_time_millis()
    overflow = 1000
    flood_size = const._MAX_CACHE_RECORDS + overflow

    cache.async_add_records(_addr(f"flood-{i}.local.", i, created=now + i) for i in range(flood_size))

    total = sum(len(store) for store in cache.cache.values())
    assert total == const._MAX_CACHE_RECORDS
    assert cache._total_records == const._MAX_CACHE_RECORDS
    # FIFO-ish: the earliest-created records (closest to expiration) get
    # evicted first, so the names that remain are from the tail.
    for i in range(overflow):
        assert f"flood-{i}.local." not in cache.cache
    for i in range(flood_size - overflow, flood_size):
        assert f"flood-{i}.local." in cache.cache


def test_cache_eviction_empty_heap_returns_without_evicting() -> None:
    """Eviction tolerates an empty ``_expire_heap`` (invariant-violation safety net)."""
    cache = r.DNSCache()
    # By the cache invariant every record in ``_total_records`` has a heap
    # entry, so eviction should never see an empty heap. Force the broken
    # state directly to pin the defensive behaviour: ``_async_evict_oldest``
    # returns without raising and the subsequent insert still lands. Since
    # eviction can't free space, the counter is allowed to drift past the
    # cap by exactly one — pinned so a future change to the recovery
    # semantics (e.g., refusing the add or clamping) fails this test.
    cache._total_records = const._MAX_CACHE_RECORDS
    cache._expire_heap = []
    cache.async_add_records([_addr("post-empty.local.", 0)])
    assert "post-empty.local." in cache.cache
    assert cache._total_records == const._MAX_CACHE_RECORDS + 1


def test_cache_eviction_skips_stale_heap_entries() -> None:
    """Eviction skips stale heap entries left by TTL re-adds."""
    cache = r.DNSCache()
    now = r.current_time_millis()
    cache.async_add_records(
        _addr(f"stale-{i}.local.", i, created=now + i) for i in range(const._MAX_CACHE_RECORDS)
    )
    assert cache._total_records == const._MAX_CACHE_RECORDS

    # Re-add the closest-to-expiration record with a longer TTL; the prior
    # ``(when, record)`` tuple stays as stale, eviction must skip it.
    victim_name = "stale-0.local."
    cache.async_add_records([_addr(victim_name, 0, ttl=7200, created=now)])
    assert cache._total_records == const._MAX_CACHE_RECORDS

    cache.async_add_records([_addr("trigger.local.", 0xFFFF, created=now + const._MAX_CACHE_RECORDS)])
    assert cache._total_records == const._MAX_CACHE_RECORDS
    assert victim_name in cache.cache
    assert "stale-1.local." not in cache.cache


def test_cache_eviction_victim_shares_key_with_new_record() -> None:
    """Inserting a record whose key collides with the eviction victim keeps it reachable."""
    cache = r.DNSCache()
    now = r.current_time_millis()
    cache.async_add_records(
        _addr(f"filler-{i}.local.", i, created=now + 1000 + i) for i in range(const._MAX_CACHE_RECORDS - 1)
    )

    # Insert at "shared.local." with the earliest expiration so eviction
    # picks it. ``_remove_key`` then deletes ``cache["shared.local."]``.
    shared_key = "shared.local."
    cache.async_add_records([_addr(shared_key, 0x0102, created=now)])
    assert cache._total_records == const._MAX_CACHE_RECORDS

    # Adding a new record under the SAME key: a pre-eviction-captured
    # ``store`` would write into an orphaned dict; the fix re-resolves.
    new_shared = _addr(shared_key, 0x0506, created=now + 999)
    cache.async_add_records([new_shared])

    assert shared_key in cache.cache, "new record orphaned: cache bucket missing"
    assert new_shared in cache.cache[shared_key]
    assert cache.async_get_unique(new_shared) == new_shared
    total = sum(len(store) for store in cache.cache.values())
    assert total == cache._total_records


def test_cache_dnsnsec_flood_is_bounded() -> None:
    """DNSNsec records honour ``_MAX_CACHE_RECORDS`` (no bypass via the ``new`` flag)."""
    cache = r.DNSCache()
    overflow = 100
    cache.async_add_records(
        r.DNSNsec(
            f"nsec-{i}.local.",
            const._TYPE_NSEC,
            const._CLASS_IN,
            120,
            f"nsec-{i}.local.",
            [const._TYPE_A],
        )
        for i in range(const._MAX_CACHE_RECORDS + overflow)
    )
    assert cache._total_records == const._MAX_CACHE_RECORDS
    total = sum(len(store) for store in cache.cache.values())
    assert total == const._MAX_CACHE_RECORDS


def test_cache_re_add_flood_does_not_grow_heap_unbounded() -> None:
    """Replaying cached records with shifting TTLs cannot grow ``_expire_heap`` unbounded."""
    cache = r.DNSCache()
    now = r.current_time_millis()
    # Stay below the cache cap so eviction never fires; the attack here is
    # heap growth via re-add, not cap saturation. Clear the
    # ``_MIN_SCHEDULED_RECORD_EXPIRATION`` floor so the rebuild engages.
    record_count = 200
    cache.async_add_records(_addr(f"flood-{i}.local.", i, created=now) for i in range(record_count))
    assert cache._total_records == record_count

    # 10 cycles x ``record_count`` stale pushes each. Without
    # ``_maybe_rebuild_heap`` firing inside ``_async_add``, the heap would
    # grow to ~11 x record_count.
    for cycle in range(10):
        cache.async_add_records(
            _addr(f"flood-{i}.local.", i, ttl=7200 + cycle, created=now) for i in range(record_count)
        )

    # Heap is bounded near the rebuild threshold; ``+ record_count`` of slack
    # to stay resilient to where in a re-add cycle the rebuild last fired.
    assert len(cache._expire_heap) <= 2 * len(cache._expirations) + record_count
    assert cache._total_records == record_count


def test_cache_eviction_decrements_total_records() -> None:
    """Natural removal (goodbyes, expirations) keeps ``_total_records`` in sync."""
    cache = r.DNSCache()
    now = r.current_time_millis()
    records = [_addr(f"sync-{i}.local.", i, created=now) for i in range(50)]
    cache.async_add_records(records)
    assert cache._total_records == 50

    cache.async_remove_records(records[:20])
    assert cache._total_records == 30

    cache.async_expire(now + (200 * 1000))
    assert cache._total_records == 0
    assert not cache.cache


def test_cache_total_records_invariant_under_mixed_ops() -> None:
    """``_total_records`` stays equal to the sum of bucket sizes across all touched paths."""
    cache = r.DNSCache()
    now = r.current_time_millis()

    def actual() -> int:
        return sum(len(store) for store in cache.cache.values())

    addrs = [_addr(f"mix-{i}.local.", i, created=now + i) for i in range(20)]
    cache.async_add_records(addrs)
    assert cache._total_records == actual() == 20

    # Re-add of an identical record: no increment.
    cache.async_add_records([addrs[0]])
    assert cache._total_records == actual() == 20

    # DNSService writes service_cache too — counter still matches cache size.
    svc = r.DNSService("svc.local.", const._TYPE_SRV, const._CLASS_IN, 120, 0, 0, 80, "host.local.")
    cache.async_add_records([svc])
    assert cache._total_records == actual() == 21
    cache.async_remove_records([svc])
    assert cache._total_records == actual() == 20

    # DNSNsec is stored but excluded from the "new" return; counter tracks it anyway.
    nsec = r.DNSNsec("nsec.local.", const._TYPE_NSEC, const._CLASS_IN, 120, "nsec.local.", [const._TYPE_A])
    cache.async_add_records([nsec])
    assert cache._total_records == actual() == 21
    cache.async_remove_records([nsec])
    assert cache._total_records == actual() == 20

    # Shared-key insert/remove: emptying the bucket drops the cache key but
    # counter decrements only by the records that left.
    shared_a = _addr("shared.local.", 0x0101, created=now)
    shared_b = _addr("shared.local.", 0x0202, created=now)
    cache.async_add_records([shared_a, shared_b])
    assert cache._total_records == actual() == 22
    cache.async_remove_records([shared_a, shared_b])
    assert cache._total_records == actual() == 20
    assert "shared.local." not in cache.cache

    cache.async_expire(now + (200 * 1000))
    assert cache._total_records == actual() == 0
    assert not cache.cache

    # Full-cap eviction loop: counter never grows past the cap, never drifts.
    cap_records = [_addr(f"cap-{i}.local.", i, created=now + i) for i in range(const._MAX_CACHE_RECORDS + 50)]
    for rec in cap_records:
        cache.async_add_records([rec])
        assert cache._total_records == actual()
    assert cache._total_records == const._MAX_CACHE_RECORDS
