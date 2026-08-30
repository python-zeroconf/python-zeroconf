"""A pure python implementation of multicast DNS service discovery.

Licensed under LGPL-2.1-or-later; see COPYING for details. This file is
part of a continuously modified work; modification dates are recorded
in the project's git history.
"""

from __future__ import annotations

from collections.abc import Iterable
from heapq import heapify, heappop, heappush
from typing import cast

from ._dns import (
    DNSAddress,
    DNSEntry,
    DNSHinfo,
    DNSNsec,
    DNSPointer,
    DNSRecord,
    DNSService,
    DNSText,
)
from ._utils.time import current_time_millis
from .const import _MAX_CACHE_RECORDS, _ONE_SECOND, _TYPE_PTR

_UNIQUE_RECORD_TYPES = (DNSAddress, DNSHinfo, DNSPointer, DNSText, DNSService)
_UniqueRecordsType = DNSAddress | DNSHinfo | DNSPointer | DNSText | DNSService
_DNSRecordCacheType = dict[str, dict[DNSRecord, DNSRecord]]
_UniqueType = tuple[str, int, int]
_DNSRecord = DNSRecord
_str = str
_float = float
_int = int

# The minimum number of scheduled record expirations before we start cleaning up
# the expiration heap. This is a performance optimization to avoid cleaning up the
# heap too often when there are only a few scheduled expirations.
_MIN_SCHEDULED_RECORD_EXPIRATION = 100


def _remove_key(cache: _DNSRecordCacheType, key: _str, record: _DNSRecord) -> None:
    """Remove a key from a DNSRecord cache

    This function must be run in from event loop.
    """
    record_cache = cache[key]
    del record_cache[record]
    if not record_cache:
        del cache[key]


class DNSCache:
    """Store of received DNS records, indexed for fast lookup."""

    def __init__(self) -> None:
        self.cache: _DNSRecordCacheType = {}
        self._expire_heap: list[tuple[float, DNSRecord]] = []
        self._expirations: dict[DNSRecord, float] = {}
        self.service_cache: _DNSRecordCacheType = {}
        self._total_records: int = 0

    # Functions prefixed with async_ are NOT threadsafe and must
    # be run in the event loop.

    def async_add_records(self, entries: Iterable[DNSRecord]) -> bool:
        """Add multiple records.

        Returns true if any of the records were not in the cache.

        This function must be run in from event loop.
        """
        new = False
        for entry in entries:
            if self._async_add(entry):
                new = True
        return new

    def async_all_by_details(self, name: _str, type_: _int, class_: _int) -> list[DNSRecord]:
        """Gets all matching entries by details.

        This function is not thread-safe and must be called from
        the event loop.
        """
        key = name.lower()
        records = self.cache.get(key)
        matches: list[DNSRecord] = []
        if records is None:
            return matches
        for record in records.values():
            if type_ == record.type and class_ == record.class_:
                matches.append(record)
        return matches

    def async_entries_with_name(self, name: str) -> list[DNSRecord]:
        """All cached records for a name; event loop only, not threadsafe."""
        return self.entries_with_name(name)

    def async_entries_with_server(self, name: str) -> list[DNSRecord]:
        """All cached records for a server name; event loop only, not threadsafe."""
        return self.entries_with_server(name)

    # The below functions are threadsafe and do not need to be run in the
    # event loop, however they all make copies so they significantly
    # inefficient.

    def async_expire(self, now: _float) -> list[DNSRecord]:
        """Purge expired entries from the cache.

        This function must be run in from event loop.

        :param now: The current time in milliseconds.
        """
        if not self._expire_heap:
            return []

        expired: list[DNSRecord] = []
        while self._expire_heap:
            when_record = self._expire_heap[0]
            when = when_record[0]
            if when > now:
                break
            heappop(self._expire_heap)
            # Skip entries left behind by a TTL re-add; the live tuple is
            # later in the heap and will be removed when it reaches the top.
            record = when_record[1]
            if self._expirations.get(record) == when:
                expired.append(record)

        self._maybe_rebuild_heap()
        self.async_remove_records(expired)
        return expired

    def async_get_unique(self, entry: _UniqueRecordsType) -> DNSRecord | None:
        """Look up the cached copy of a unique record, or None.

        Event loop only; not threadsafe.
        """
        store = self.cache.get(entry.key)
        if store is None:
            return None
        return store.get(entry)

    def async_mark_unique_records_older_than_1s_to_expire(
        self,
        unique_types: set[_UniqueType],
        answers: Iterable[DNSRecord],
        now: _float,
    ) -> None:
        # rfc6762#section-10.2 para 2
        # Since unique is set, all old records with that name, rrtype,
        # and rrclass that were received more than one second ago are declared
        # invalid, and marked to expire from the cache in one second.
        answers_rrset = set(answers)
        for name, type_, class_ in unique_types:
            for record in self.async_all_by_details(name, type_, class_):
                created_double = record.created
                if (now - created_double > _ONE_SECOND) and record not in answers_rrset:
                    # Expire in 1s
                    self._async_set_created_ttl(record, now, 1)

    def async_remove_records(self, entries: Iterable[DNSRecord]) -> None:
        """Remove multiple records.

        This function must be run in from event loop.
        """
        for entry in entries:
            self._async_remove(entry)

    def current_entry_with_name_and_alias(self, name: str, alias: str) -> DNSRecord | None:
        now = current_time_millis()
        for record in reversed(self.entries_with_name(name)):
            if (
                record.type == _TYPE_PTR
                and not record.is_expired(now)
                and cast(DNSPointer, record).alias == alias
            ):
                return record
        return None

    def entries_with_name(self, name: str) -> list[DNSRecord]:
        if entries := self.cache.get(name.lower()):
            return list(entries.values())
        return []

    def entries_with_server(self, server: str) -> list[DNSRecord]:
        """All cached records whose server field matches."""
        if entries := self.service_cache.get(server.lower()):
            return list(entries.values())
        return []

    def get(self, entry: DNSEntry) -> DNSRecord | None:
        if isinstance(entry, _UNIQUE_RECORD_TYPES):
            return self.cache.get(entry.key, {}).get(entry)
        for cached_entry in reversed(list(self.cache.get(entry.key, {}).values())):
            if entry.__eq__(cached_entry):
                return cached_entry
        return None

    def get_all_by_details(self, name: str, type_: _int, class_: _int) -> list[DNSRecord]:
        """Return every cached record carrying this name, type and class."""
        key = name.lower()
        records = self.cache.get(key)
        if records is None:
            return []
        return [entry for entry in list(records.values()) if type_ == entry.type and class_ == entry.class_]

    def get_by_details(self, name: str, type_: _int, class_: _int) -> DNSRecord | None:
        """Gets the first matching entry by details. Returns None if no entries match.

        Calling this function is not recommended as it will only
        return one record even if there are multiple entries.

        For example if there are multiple A or AAAA addresses this
        function will return the last one that was added to the cache
        which may not be the one you expect.

        Use get_all_by_details instead.
        """
        key = name.lower()
        records = self.cache.get(key)
        if records is None:
            return None
        for cached_entry in reversed(list(records.values())):
            if type_ == cached_entry.type and class_ == cached_entry.class_:
                return cached_entry
        return None

    def names(self) -> list[str]:
        """Return a copy of the list of current cache names."""
        return list(self.cache)

    def _async_add(self, record: _DNSRecord) -> bool:
        """Store a record, returning True when it was not cached before.

        Event loop only; not threadsafe.
        """
        # Previously storage of records was implemented as a list
        # instead a dict. Since DNSRecords are now hashable, the implementation
        # uses a dict to ensure that adding a new record to the cache
        # replaces any existing records that are __eq__ to each other which
        # removes the risk that accessing the cache from the wrong
        # direction would return the old incorrect entry.
        store = self.cache.get(record.key)
        is_new = store is None or record not in store
        # Bound total cache size; evict closest-to-expiration entry to
        # make room before inserting a new record. Prevents a LAN-local
        # flood of unique-name records from growing the cache without
        # bound (RFC 6762 §10 advisory caching, defense-in-depth).
        if is_new and self._total_records >= _MAX_CACHE_RECORDS:
            self._async_evict_oldest()
            # The victim may have been the last record under
            # ``record.key``, in which case ``_remove_key`` deleted
            # the bucket. Re-fetch before creating below.
            store = self.cache.get(record.key)
        if store is None:
            store = self.cache[record.key] = {}
        new = is_new and not isinstance(record, DNSNsec)
        if is_new:
            self._total_records += 1
        store[record] = record
        when = record.created + (record.ttl * 1000)
        if self._expirations.get(record) != when:
            heappush(self._expire_heap, (when, record))
            self._expirations[record] = when
            # Re-adds of an existing record with a new TTL push a fresh
            # entry but leave the prior tuple behind as stale, so a peer
            # that just replays cached records can grow ``_expire_heap``
            # without ever tripping the cap. Rebuild when stale entries
            # dominate.
            self._maybe_rebuild_heap()

        if isinstance(record, DNSService):
            service_record = record
            if (service_store := self.service_cache.get(service_record.server_key)) is None:
                service_store = self.service_cache[service_record.server_key] = {}
            service_store[service_record] = service_record
        return new

    def _async_evict_oldest(self) -> None:
        """Drop the closest-to-expiration record to make room for a new one."""
        while self._expire_heap:
            when_record = heappop(self._expire_heap)
            record = when_record[1]
            if self._expirations.get(record) != when_record[0]:
                continue
            self._async_remove(record)
            return

    def _async_remove(self, record: _DNSRecord) -> None:
        """Drop a record from the cache. Event loop only; not threadsafe."""
        if isinstance(record, DNSService):
            service_record = record
            _remove_key(self.service_cache, service_record.server_key, service_record)
        _remove_key(self.cache, record.key, record)
        self._expirations.pop(record, None)
        self._total_records -= 1

    def _async_set_created_ttl(self, record: DNSRecord, now: _float, ttl: _int) -> None:
        """Stamp a record with a new ttl and creation moment, then cache it."""
        # It would be better if we made a copy instead of mutating the record
        # in place, but records currently don't have a copy method.
        record._set_created_ttl(now, ttl)
        self._async_add(record)

    def _maybe_rebuild_heap(self) -> None:
        """Rebuild ``_expire_heap`` when stale entries dominate live ones."""
        expire_heap_len = len(self._expire_heap)
        if (
            expire_heap_len > _MIN_SCHEDULED_RECORD_EXPIRATION
            and expire_heap_len > len(self._expirations) * 2
        ):
            self._expire_heap = [
                entry for entry in self._expire_heap if self._expirations.get(entry[1]) == entry[0]
            ]
            heapify(self._expire_heap)
