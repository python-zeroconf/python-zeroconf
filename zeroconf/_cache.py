""" Multicast DNS Service Discovery for Python, v0.14-wmcbrine
    Copyright 2003 Paul Scott-Murphy, 2014 William McBrine

    This module provides a framework for the use of DNS Service Discovery
    using IP multicast.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
    USA
"""

import itertools
from typing import Dict, Iterable, List, Optional, Union, cast

from ._dns import DNSAddress, DNSEntry, DNSHinfo, DNSPointer, DNSRecord, DNSService, DNSText
from ._utils.time import current_time_millis
from .const import _TYPE_PTR

_UNIQUE_RECORD_TYPES = (DNSAddress, DNSHinfo, DNSPointer, DNSText, DNSService)
_UniqueRecordsType = Union[DNSAddress, DNSHinfo, DNSPointer, DNSText, DNSService]
_DNSRecordCacheType = Dict[str, Dict[DNSRecord, DNSRecord]]


def _remove_key(cache: _DNSRecordCacheType, key: str, entry: DNSRecord) -> None:
    """Remove a key from a DNSRecord cache

    This function must be run in from event loop.
    """
    del cache[key][entry]
    if not cache[key]:
        del cache[key]


class DNSCache:
    """A cache of DNS entries."""

    def __init__(self) -> None:
        self.cache: _DNSRecordCacheType = {}
        self.service_cache: _DNSRecordCacheType = {}

    # Functions prefixed with async_ are NOT threadsafe and must
    # be run in the event loop.

    def _async_add(self, entry: DNSRecord) -> None:
        """Adds an entry.

        This function must be run in from event loop.
        """
        # Previously storage of records was implemented as a list
        # instead a dict. Since DNSRecords are now hashable, the implementation
        # uses a dict to ensure that adding a new record to the cache
        # replaces any existing records that are __eq__ to each other which
        # removes the risk that accessing the cache from the wrong
        # direction would return the old incorrect entry.
        self.cache.setdefault(entry.key, {})[entry] = entry
        if isinstance(entry, DNSService):
            self.service_cache.setdefault(entry.server, {})[entry] = entry

    def async_add_records(self, entries: Iterable[DNSRecord]) -> None:
        """Add multiple records.

        This function must be run in from event loop.
        """
        for entry in entries:
            self._async_add(entry)

    def _async_remove(self, entry: DNSRecord) -> None:
        """Removes an entry.

        This function must be run in from event loop.
        """
        if isinstance(entry, DNSService):
            _remove_key(self.service_cache, entry.server, entry)
        _remove_key(self.cache, entry.key, entry)

    def async_remove_records(self, entries: Iterable[DNSRecord]) -> None:
        """Remove multiple records.

        This function must be run in from event loop.
        """
        for entry in entries:
            self._async_remove(entry)

    def async_expire(self, now: float) -> List[DNSRecord]:
        """Purge expired entries from the cache.

        This function must be run in from event loop.
        """
        expired = [record for record in itertools.chain(*self.cache.values()) if record.is_expired(now)]
        self.async_remove_records(expired)
        return expired

    def async_get(self, entry: DNSEntry) -> Optional[DNSRecord]:
        """Gets an entry by key.  Will return None if there is no
        matching entry.

        This function is not threadsafe and must be called from
        the event loop.
        """
        if isinstance(entry, _UNIQUE_RECORD_TYPES):
            return self._lookup_unique_entry_threadsafe(entry)
        return self._async_get(entry)

    def async_get_all_by_details(self, name: str, type_: int, class_: int) -> List[DNSRecord]:
        """Gets all matching entries by details.

        This function is not threadsafe and must be called from
        the event loop.
        """
        match_entry = DNSEntry(name, type_, class_)
        return [entry for entry in self.cache.get(match_entry.key, []) if match_entry.__eq__(entry)]

    def async_entries_with_name(self, name: str) -> Dict[DNSRecord, DNSRecord]:
        """Returns a dict of entries whose key matches the name.

        This function is not threadsafe and must be called from
        the event loop.
        """
        return self.cache.get(name.lower(), {})

    def async_entries_with_server(self, name: str) -> Dict[DNSRecord, DNSRecord]:
        """Returns a dict of entries whose key matches the server.

        This function is not threadsafe and must be called from
        the event loop.
        """
        return self.service_cache.get(name.lower(), {})

    def _async_get(self, entry: DNSEntry) -> Optional[DNSRecord]:
        """Search a dict of entries by making a copy of it first.

        This function is not threadsafe and must be called from
        the event loop.
        """
        for cached_entry in self.cache.get(entry.key, []):
            if entry.__eq__(cached_entry):
                return cached_entry
        return None

    # The below functions are threadsafe and do not need to be run in the
    # event loop, however they all make copies so they significantly
    # inefficent

    def _lookup_unique_entry_threadsafe(self, entry: _UniqueRecordsType) -> Optional[DNSRecord]:
        """Lookup a unique entry threadsafe."""
        return self.cache.get(entry.key, {}).get(entry)

    def _get_threadsafe(self, entry: DNSEntry) -> Optional[DNSRecord]:
        """Search a dict of entries by making a copy of it first."""
        for cached_entry in reversed(list(self.cache.get(entry.key, []))):
            if entry.__eq__(cached_entry):
                return cached_entry
        return None

    def get(self, entry: DNSEntry) -> Optional[DNSRecord]:
        """Gets an entry by key.  Will return None if there is no
        matching entry."""
        if isinstance(entry, _UNIQUE_RECORD_TYPES):
            return self._lookup_unique_entry_threadsafe(entry)
        return self._get_threadsafe(entry)

    def get_by_details(self, name: str, type_: int, class_: int) -> Optional[DNSRecord]:
        """Gets the first matching entry by details. Returns None if no entries match.

        Calling this function is not recommended as it will only
        return one record even if there are multiple entries.

        For example if there are multiple A or AAAA addresses this
        function will return the last one that was added to the cache
        which may not be the one you expect.

        Use get_all_by_details instead.
        """
        return self.get(DNSEntry(name, type_, class_))

    def get_all_by_details(self, name: str, type_: int, class_: int) -> List[DNSRecord]:
        """Gets all matching entries by details."""
        match_entry = DNSEntry(name, type_, class_)
        return [entry for entry in list(self.cache.get(match_entry.key, [])) if match_entry.__eq__(entry)]

    def entries_with_server(self, server: str) -> List[DNSRecord]:
        """Returns a list of entries whose server matches the name."""
        return list(self.service_cache.get(server.lower(), []))

    def entries_with_name(self, name: str) -> List[DNSRecord]:
        """Returns a list of entries whose key matches the name."""
        return list(self.cache.get(name.lower(), []))

    def current_entry_with_name_and_alias(self, name: str, alias: str) -> Optional[DNSRecord]:
        now = current_time_millis()
        for record in reversed(self.entries_with_name(name)):
            if (
                record.type == _TYPE_PTR
                and not record.is_expired(now)
                and cast(DNSPointer, record).alias == alias
            ):
                return record
        return None

    def names(self) -> List[str]:
        """Return a copy of the list of current cache names."""
        return list(self.cache)
