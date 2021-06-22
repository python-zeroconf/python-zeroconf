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

import enum
import socket
from typing import Any, Dict, Iterable, Optional, TYPE_CHECKING, Tuple, Union, cast

from ._exceptions import AbstractMethodException
from ._utils.net import _is_v6_address
from ._utils.time import current_time_millis, millis_to_seconds
from .const import (
    _CLASSES,
    _CLASS_MASK,
    _CLASS_UNIQUE,
    _EXPIRE_FULL_TIME_PERCENT,
    _EXPIRE_STALE_TIME_PERCENT,
    _RECENT_TIME_PERCENT,
    _TYPES,
    _TYPE_ANY,
)

_LEN_BYTE = 1
_LEN_SHORT = 2
_LEN_INT = 4

_BASE_MAX_SIZE = _LEN_SHORT + _LEN_SHORT + _LEN_INT + _LEN_SHORT  # type  # class  # ttl  # length
_NAME_COMPRESSION_MIN_SIZE = _LEN_BYTE * 2

if TYPE_CHECKING:
    # https://github.com/PyCQA/pylint/issues/3525
    from ._protocol import DNSIncoming, DNSOutgoing  # pylint: disable=cyclic-import


@enum.unique
class DNSQuestionType(enum.Enum):
    """An MDNS question type.

    "QU" - questions requesting unicast responses
    "QM" - questions requesting multicast responses
    https://datatracker.ietf.org/doc/html/rfc6762#section-5.4
    """

    QU = 1
    QM = 2


def dns_entry_matches(record: 'DNSEntry', key: str, type_: int, class_: int) -> bool:
    return key == record.key and type_ == record.type and class_ == record.class_


class DNSEntry:

    """A DNS entry"""

    __slots__ = ('key', 'name', 'type', 'class_', 'unique')

    def __init__(self, name: str, type_: int, class_: int) -> None:
        self.key = name.lower()
        self.name = name
        self.type = type_
        self.class_ = class_ & _CLASS_MASK
        self.unique = (class_ & _CLASS_UNIQUE) != 0

    def _entry_tuple(self) -> Tuple[str, int, int]:
        """Entry Tuple for DNSEntry."""
        return (self.key, self.type, self.class_)

    def __eq__(self, other: Any) -> bool:
        """Equality test on key (lowercase name), type, and class"""
        return dns_entry_matches(other, self.key, self.type, self.class_) and isinstance(other, DNSEntry)

    @staticmethod
    def get_class_(class_: int) -> str:
        """Class accessor"""
        return _CLASSES.get(class_, "?(%s)" % class_)

    @staticmethod
    def get_type(t: int) -> str:
        """Type accessor"""
        return _TYPES.get(t, "?(%s)" % t)

    def entry_to_string(self, hdr: str, other: Optional[Union[bytes, str]]) -> str:
        """String representation with additional information"""
        return "%s[%s,%s%s,%s]%s" % (
            hdr,
            self.get_type(self.type),
            self.get_class_(self.class_),
            "-unique" if self.unique else "",
            self.name,
            "=%s" % cast(Any, other) if other is not None else "",
        )


class DNSQuestion(DNSEntry):

    """A DNS question entry"""

    def answered_by(self, rec: 'DNSRecord') -> bool:
        """Returns true if the question is answered by the record"""
        return (
            self.class_ == rec.class_
            and (self.type == rec.type or self.type == _TYPE_ANY)
            and self.name == rec.name
        )

    def __hash__(self) -> int:
        return hash((self.name, self.class_, self.type))

    @property
    def max_size(self) -> int:
        """Maximum size of the question in the packet."""
        return len(self.name.encode('utf-8')) + _LEN_BYTE + _LEN_SHORT + _LEN_SHORT  # type  # class

    @property
    def unicast(self) -> bool:
        """Returns true if the QU (not QM) is set.

        unique shares the same mask as the one
        used for unicast.
        """
        return self.unique

    @unicast.setter
    def unicast(self, value: bool) -> None:
        """Sets the QU bit (not QM)."""
        self.unique = value

    def __repr__(self) -> str:
        """String representation"""
        return "%s[question,%s,%s,%s]" % (
            self.get_type(self.type),
            "QU" if self.unicast else "QM",
            self.get_class_(self.class_),
            self.name,
        )


class DNSRecord(DNSEntry):

    """A DNS record - like a DNS entry, but has a TTL"""

    __slots__ = ('ttl', 'created', '_expiration_time', '_stale_time', '_recent_time')

    # TODO: Switch to just int ttl
    def __init__(
        self, name: str, type_: int, class_: int, ttl: Union[float, int], created: Optional[float] = None
    ) -> None:
        super().__init__(name, type_, class_)
        self.ttl = ttl
        self.created = created or current_time_millis()
        self._expiration_time: Optional[float] = None
        self._stale_time: Optional[float] = None
        self._recent_time: Optional[float] = None

    def __eq__(self, other: Any) -> bool:  # pylint: disable=no-self-use
        """Abstract method"""
        raise AbstractMethodException

    def suppressed_by(self, msg: 'DNSIncoming') -> bool:
        """Returns true if any answer in a message can suffice for the
        information held in this record."""
        return any(self.suppressed_by_answer(record) for record in msg.answers)

    def suppressed_by_answer(self, other: 'DNSRecord') -> bool:
        """Returns true if another record has same name, type and class,
        and if its TTL is at least half of this record's."""
        return self == other and other.ttl > (self.ttl / 2)

    def get_expiration_time(self, percent: int) -> float:
        """Returns the time at which this record will have expired
        by a certain percentage."""
        return self.created + (percent * self.ttl * 10)

    # TODO: Switch to just int here
    def get_remaining_ttl(self, now: float) -> Union[int, float]:
        """Returns the remaining TTL in seconds."""
        if self._expiration_time is None:
            self._expiration_time = self.get_expiration_time(_EXPIRE_FULL_TIME_PERCENT)
        return max(0, millis_to_seconds(self._expiration_time - now))

    def is_expired(self, now: float) -> bool:
        """Returns true if this record has expired."""
        if self._expiration_time is None:
            self._expiration_time = self.get_expiration_time(_EXPIRE_FULL_TIME_PERCENT)
        return self._expiration_time <= now

    def is_stale(self, now: float) -> bool:
        """Returns true if this record is at least half way expired."""
        if self._stale_time is None:
            self._stale_time = self.get_expiration_time(_EXPIRE_STALE_TIME_PERCENT)
        return self._stale_time <= now

    def is_recent(self, now: float) -> bool:
        """Returns true if the record more than one quarter of its TTL remaining."""
        if self._recent_time is None:
            self._recent_time = self.get_expiration_time(_RECENT_TIME_PERCENT)
        return self._recent_time > now

    def reset_ttl(self, other: 'DNSRecord') -> None:
        """Sets this record's TTL and created time to that of
        another record."""
        self.set_created_ttl(other.created, other.ttl)

    def set_created_ttl(self, created: float, ttl: Union[float, int]) -> None:
        """Set the created and ttl of a record."""
        self.created = created
        self.ttl = ttl
        self._expiration_time = None
        self._stale_time = None
        self._recent_time = None

    def write(self, out: 'DNSOutgoing') -> None:  # pylint: disable=no-self-use
        """Abstract method"""
        raise AbstractMethodException

    def to_string(self, other: Union[bytes, str]) -> str:
        """String representation with additional information"""
        arg = "%s/%s,%s" % (self.ttl, int(self.get_remaining_ttl(current_time_millis())), cast(Any, other))
        return DNSEntry.entry_to_string(self, "record", arg)


class DNSAddress(DNSRecord):

    """A DNS address record"""

    __slots__ = ('address', 'scope_id')

    def __init__(
        self,
        name: str,
        type_: int,
        class_: int,
        ttl: int,
        address: bytes,
        *,
        scope_id: Optional[int] = None,
        created: Optional[float] = None,
    ) -> None:
        super().__init__(name, type_, class_, ttl, created)
        self.address = address
        self.scope_id = scope_id

    def write(self, out: 'DNSOutgoing') -> None:
        """Used in constructing an outgoing packet"""
        out.write_string(self.address)

    def __eq__(self, other: Any) -> bool:
        """Tests equality on address"""
        return (
            isinstance(other, DNSAddress)
            and self.address == other.address
            and self.scope_id == other.scope_id
            and DNSEntry.__eq__(self, other)
        )

    def __hash__(self) -> int:
        """Hash to compare like DNSAddresses."""
        return hash((*self._entry_tuple(), self.address, self.scope_id))

    def __repr__(self) -> str:
        """String representation"""
        try:
            return self.to_string(
                socket.inet_ntop(
                    socket.AF_INET6 if _is_v6_address(self.address) else socket.AF_INET, self.address
                )
            )
        except (ValueError, OSError):
            return self.to_string(str(self.address))


class DNSHinfo(DNSRecord):

    """A DNS host information record"""

    __slots__ = ('cpu', 'os')

    def __init__(
        self, name: str, type_: int, class_: int, ttl: int, cpu: str, os: str, created: Optional[float] = None
    ) -> None:
        super().__init__(name, type_, class_, ttl, created)
        self.cpu = cpu
        self.os = os

    def write(self, out: 'DNSOutgoing') -> None:
        """Used in constructing an outgoing packet"""
        out.write_character_string(self.cpu.encode('utf-8'))
        out.write_character_string(self.os.encode('utf-8'))

    def __eq__(self, other: Any) -> bool:
        """Tests equality on cpu and os"""
        return (
            isinstance(other, DNSHinfo)
            and self.cpu == other.cpu
            and self.os == other.os
            and DNSEntry.__eq__(self, other)
        )

    def __hash__(self) -> int:
        """Hash to compare like DNSHinfo."""
        return hash((*self._entry_tuple(), self.cpu, self.os))

    def __repr__(self) -> str:
        """String representation"""
        return self.to_string(self.cpu + " " + self.os)


class DNSPointer(DNSRecord):

    """A DNS pointer record"""

    __slots__ = ('alias',)

    def __init__(
        self, name: str, type_: int, class_: int, ttl: int, alias: str, created: Optional[float] = None
    ) -> None:
        super().__init__(name, type_, class_, ttl, created)
        self.alias = alias

    @property
    def max_size_compressed(self) -> int:
        """Maximum size of the record in the packet assuming the name has been compressed."""
        return (
            _BASE_MAX_SIZE
            + _NAME_COMPRESSION_MIN_SIZE
            + (len(self.alias) - len(self.name))
            + _NAME_COMPRESSION_MIN_SIZE
        )

    def write(self, out: 'DNSOutgoing') -> None:
        """Used in constructing an outgoing packet"""
        out.write_name(self.alias)

    def __eq__(self, other: Any) -> bool:
        """Tests equality on alias"""
        return isinstance(other, DNSPointer) and self.alias == other.alias and DNSEntry.__eq__(self, other)

    def __hash__(self) -> int:
        """Hash to compare like DNSPointer."""
        return hash((*self._entry_tuple(), self.alias))

    def __repr__(self) -> str:
        """String representation"""
        return self.to_string(self.alias)


class DNSText(DNSRecord):

    """A DNS text record"""

    __slots__ = ('text',)

    def __init__(
        self, name: str, type_: int, class_: int, ttl: int, text: bytes, created: Optional[float] = None
    ) -> None:
        assert isinstance(text, (bytes, type(None)))
        super().__init__(name, type_, class_, ttl, created)
        self.text = text

    def write(self, out: 'DNSOutgoing') -> None:
        """Used in constructing an outgoing packet"""
        out.write_string(self.text)

    def __hash__(self) -> int:
        """Hash to compare like DNSText."""
        return hash((*self._entry_tuple(), self.text))

    def __eq__(self, other: Any) -> bool:
        """Tests equality on text"""
        return isinstance(other, DNSText) and self.text == other.text and DNSEntry.__eq__(self, other)

    def __repr__(self) -> str:
        """String representation"""
        if len(self.text) > 10:
            return self.to_string(self.text[:7]) + "..."
        return self.to_string(self.text)


class DNSService(DNSRecord):

    """A DNS service record"""

    __slots__ = ('priority', 'weight', 'port', 'server')

    def __init__(
        self,
        name: str,
        type_: int,
        class_: int,
        ttl: Union[float, int],
        priority: int,
        weight: int,
        port: int,
        server: str,
        created: Optional[float] = None,
    ) -> None:
        super().__init__(name, type_, class_, ttl, created)
        self.priority = priority
        self.weight = weight
        self.port = port
        self.server = server

    def write(self, out: 'DNSOutgoing') -> None:
        """Used in constructing an outgoing packet"""
        out.write_short(self.priority)
        out.write_short(self.weight)
        out.write_short(self.port)
        out.write_name(self.server)

    def __eq__(self, other: Any) -> bool:
        """Tests equality on priority, weight, port and server"""
        return (
            isinstance(other, DNSService)
            and self.priority == other.priority
            and self.weight == other.weight
            and self.port == other.port
            and self.server == other.server
            and DNSEntry.__eq__(self, other)
        )

    def __hash__(self) -> int:
        """Hash to compare like DNSService."""
        return hash((*self._entry_tuple(), self.priority, self.weight, self.port, self.server))

    def __repr__(self) -> str:
        """String representation"""
        return self.to_string("%s:%s" % (self.server, self.port))


class DNSRRSet:
    """A set of dns records independent of the ttl."""

    __slots__ = ('_records', '_lookup')

    def __init__(self, records: Iterable[DNSRecord]) -> None:
        """Create an RRset from records."""
        self._records = records
        self._lookup: Optional[Dict[DNSRecord, DNSRecord]] = None

    @property
    def lookup(self) -> Dict[DNSRecord, DNSRecord]:
        if self._lookup is None:
            # Build the hash table so we can lookup the record independent of the ttl
            self._lookup = {record: record for record in self._records}
        return self._lookup

    def suppresses(self, record: DNSRecord) -> bool:
        """Returns true if any answer in the rrset can suffice for the
        information held in this record."""
        other = self.lookup.get(record)
        return bool(other and other.ttl > (record.ttl / 2))

    def __contains__(self, record: DNSRecord) -> bool:
        """Returns true if the rrset contains the record."""
        return record in self.lookup
