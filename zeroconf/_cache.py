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

from typing import Dict, Iterable, List, Optional, cast

from ._dns import DNSEntry, DNSPointer, DNSRecord, DNSService
from ._utils.time import current_time_millis
from .const import _TYPE_PTR


class DNSCache:
    """A cache of DNS entries."""

    def __init__(self) -> None:
        self.cache: Dict[str, List[DNSRecord]] = {}
        self.service_cache: Dict[str, List[DNSRecord]] = {}

    def add(self, entry: DNSRecord) -> None:
        """Adds an entry"""
        # Insert last in list, get will return newest entry
        # iteration will result in last update winning
        self.cache.setdefault(entry.key, {})[entry] = entry
        if isinstance(entry, DNSService):
            self.service_cache.setdefault(entry.server, {})[entry] = entry

    def add_records(self, entries: Iterable[DNSRecord]) -> None:
        """Add multiple records."""
        for entry in entries:
            self.add(entry)

    def remove(self, entry: DNSRecord) -> None:
        """Removes an entry."""
        if isinstance(entry, DNSService):
            DNSCache.remove_key(self.service_cache, entry.server, entry)
        DNSCache.remove_key(self.cache, entry.key, entry)

    def remove_records(self, entries: Iterable[DNSRecord]) -> None:
        """Remove multiple records."""
        for entry in entries:
            self.remove(entry)

    @staticmethod
    def remove_key(cache: dict, key: str, entry: DNSRecord) -> None:
        """Forgiving remove of a cache key."""
        try:
            del cache[key][entry]
            if not cache[key]:
                del cache[key]
        except (KeyError, ValueError):
            pass

    def get(self, entry: DNSEntry) -> Optional[DNSRecord]:
        """Gets an entry by key.  Will return None if there is no
        matching entry."""
        for cached_entry in reversed(self.entries_with_name(entry.key)):
            if entry.__eq__(cached_entry):
                return cached_entry
        return None

    def get_by_details(self, name: str, type_: int, class_: int) -> Optional[DNSRecord]:
        """Gets the first matching entry by details. Returns None if no entries match."""
        return self.get(DNSEntry(name, type_, class_))

    def get_all_by_details(self, name: str, type_: int, class_: int) -> List[DNSRecord]:
        """Gets all matching entries by details."""
        match_entry = DNSEntry(name, type_, class_)
        return [entry for entry in self.entries_with_name(name) if match_entry.__eq__(entry)]

    def entries_with_server(self, server: str) -> List[DNSRecord]:
        """Returns a list of entries whose server matches the name."""
        return self.service_cache.get(server, {}).copy()

    def entries_with_name(self, name: str) -> List[DNSRecord]:
        """Returns a list of entries whose key matches the name."""
        return self.cache.get(name.lower(), {}).copy()

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

    def expire(self, now: float) -> Iterable[DNSRecord]:
        """Purge expired entries from the cache."""
        for name in self.names():
            for record in self.entries_with_name(name):
                if record.is_expired(now):
                    self.remove(record)
                    yield record
