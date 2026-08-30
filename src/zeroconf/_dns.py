"""A pure python implementation of multicast DNS service discovery.

Licensed under LGPL-2.1-or-later; see COPYING for details. This file is
part of a continuously modified work; modification dates are recorded
in the project's git history.
"""

from __future__ import annotations

import enum
import socket
from typing import TYPE_CHECKING, Any

from ._exceptions import AbstractMethodException
from ._utils.net import _is_v6_address
from ._utils.time import current_time_millis
from .const import _CLASS_MASK, _CLASS_UNIQUE, _CLASSES, _TYPE_ANY, _TYPES

_LEN_BYTE = 1
_LEN_SHORT = 2
_LEN_INT = 4

_BASE_MAX_SIZE = _LEN_SHORT + _LEN_SHORT + _LEN_INT + _LEN_SHORT  # type  # class  # ttl  # length
_NAME_COMPRESSION_MIN_SIZE = _LEN_BYTE * 2

_EXPIRE_FULL_TIME_MS = 1000
_EXPIRE_STALE_TIME_MS = 500
_RECENT_TIME_MS = 250

_float = float
_int = int


# Longest TXT payload rendered inline by repr; larger payloads are
# summarized as a byte count to keep debug logs readable.
_TEXT_REPR_INLINE_LIMIT = 16


def _type_label(type_: int) -> str:
    return _TYPES.get(type_, f"unknown-type-{type_}")


def _class_label(class_: int) -> str:
    return _CLASSES.get(class_, f"unknown-class-{class_}")


def _format_display(kind: str, fields: list[tuple[str, str]], data: bytes | str | None = None) -> str:
    if data is not None:
        fields = [*fields, ("data", str(data))]
    body = " ".join([f"{key}={value}" if key else value for key, value in fields])
    return f"<{kind} {body}>"


if TYPE_CHECKING:
    from ._protocol.incoming import DNSIncoming
    from ._protocol.outgoing import DNSOutgoing


@enum.unique
class DNSQuestionType(enum.Enum):
    """An MDNS question type.

    "QU" - questions requesting unicast responses
    "QM" - questions requesting multicast responses
    https://datatracker.ietf.org/doc/html/rfc6762#section-5.4
    """

    QU = 1
    QM = 2


class DNSEntry:  # noqa: PLW1641
    """Identity shared by every question and record: name, type and class."""

    __slots__ = ("class_", "key", "name", "type", "unique")

    def __init__(self, name: str, type_: int, class_: int) -> None:
        self._fast_init_entry(name, type_, class_)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, DNSEntry) and self._dns_entry_matches(other)

    @property
    def class_label(self) -> str:
        """Human readable label for the record class."""
        return _class_label(self.class_)

    def entry_to_string(self, kind: str, extra: bytes | str | None) -> str:
        """Compatibility alias for the display formatter."""
        return _format_display(kind, self._display_fields(), extra)

    @staticmethod
    def get_class_(class_: int) -> str:
        """Compatibility alias for the class_label property."""
        return _class_label(class_)

    @staticmethod
    def get_type(t: int) -> str:
        """Compatibility alias for the type_label property."""
        return _type_label(t)

    @property
    def type_label(self) -> str:
        """Human readable label for the record type."""
        return _type_label(self.type)

    def _display_fields(self) -> list[tuple[str, str]]:
        fields = [("name", self.name), ("type", self.type_label), ("class", self.class_label)]
        if self.unique:
            fields.append(("", "unique"))
        return fields

    def _dns_entry_matches(self, other: DNSEntry) -> bool:
        return self.key == other.key and self.type == other.type and self.class_ == other.class_

    def _fast_init_entry(self, name: str, type_: _int, class_: _int) -> None:
        """Fast init for reuse."""
        self.name = name
        self.key = name.lower()
        self.type = type_
        self.class_ = class_ & _CLASS_MASK
        self.unique = (class_ & _CLASS_UNIQUE) != 0


class DNSQuestion(DNSEntry):
    """A question a resolver asks about a name."""

    __slots__ = ("_hash",)

    def __init__(self, name: str, type_: int, class_: int) -> None:
        self._fast_init(name, type_, class_)

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, DNSQuestion) and self._dns_entry_matches(other)

    def __hash__(self) -> int:
        return self._hash

    def __repr__(self) -> str:
        mode = "QU" if self.unicast else "QM"
        return _format_display("DNSQuestion", [("mode", mode), *self._display_fields()])

    def answered_by(self, rec: DNSRecord) -> bool:
        return self.class_ == rec.class_ and self.type in (rec.type, _TYPE_ANY) and self.name == rec.name

    @property
    def max_size(self) -> int:
        """Maximum size of the question in the packet."""
        return len(self.name.encode("utf-8")) + _LEN_BYTE + _LEN_SHORT + _LEN_SHORT

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

    def _fast_init(self, name: str, type_: _int, class_: _int) -> None:
        """Fast init for reuse."""
        self._fast_init_entry(name, type_, class_)
        self._hash = hash((self.key, type_, self.class_))


class DNSRecord(DNSEntry):  # noqa: PLW1641
    """Record layered on the entry identity with a TTL and creation time."""

    __slots__ = ("created", "ttl")

    def __init__(
        self,
        name: str,
        type_: int,
        class_: int,
        ttl: _int,
        created: float | None = None,
    ) -> None:
        self._fast_init_record(name, type_, class_, ttl, created or current_time_millis())

    def __eq__(self, other: Any) -> bool:
        raise AbstractMethodException(f"{type(self).__name__} is missing __eq__")

    def __lt__(self, other: DNSRecord) -> bool:
        return self.ttl < other.ttl

    def get_expiration_time(self, percent: _int) -> float:
        """Return the moment when the given percentage of the TTL has elapsed."""
        # created is epoch milliseconds and ttl is seconds, so one percent
        # of the ttl expressed in milliseconds is ttl * 10
        return self.created + percent * self.ttl * 10

    # TODO: Switch to just int here
    def get_remaining_ttl(self, now: _float) -> int | float:
        """Seconds of TTL left at the given time, never negative."""
        remain = (self.created + (_EXPIRE_FULL_TIME_MS * self.ttl) - now) / 1000.0
        return 0 if remain < 0 else remain

    def is_expired(self, now: _float) -> bool:
        """True once the full TTL has elapsed."""
        return self.created + (_EXPIRE_FULL_TIME_MS * self.ttl) <= now

    def is_recent(self, now: _float) -> bool:
        """Returns true if the record more than one quarter of its TTL remaining."""
        return self.created + (_RECENT_TIME_MS * self.ttl) > now

    def is_stale(self, now: _float) -> bool:
        return self.created + (_EXPIRE_STALE_TIME_MS * self.ttl) <= now

    def suppressed_by(self, msg: DNSIncoming) -> bool:
        answers = msg.answers()
        for record in answers:
            if self._suppressed_by_answer(record):
                return True
        return False

    def to_string(self, other: bytes | str) -> str:
        """Compatibility alias for the display formatter."""
        return _format_display(type(self).__name__, self._display_fields(), other)

    def write(self, out: DNSOutgoing) -> None:
        raise AbstractMethodException(f"{type(self).__name__} is missing write")

    def _display_fields(self) -> list[tuple[str, str]]:
        remaining = int(self.get_remaining_ttl(current_time_millis()))
        return [*DNSEntry._display_fields(self), ("ttl", f"{self.ttl} ({remaining} remaining)")]

    def _fast_init_record(self, name: str, type_: _int, class_: _int, ttl: _int, created: _float) -> None:
        """Fast init for reuse."""
        self._fast_init_entry(name, type_, class_)
        self.ttl = ttl
        self.created = created

    def _repr_with(self, *details: tuple[str, str]) -> str:
        return _format_display(type(self).__name__, [*self._display_fields(), *details])

    def _set_created_ttl(self, created: _float, ttl: _int) -> None:
        # It would be better if we made a copy instead of mutating the record
        # in place, but records currently don't have a copy method.
        self.created = created
        self.ttl = ttl

    def _suppressed_by_answer(self, answer: DNSRecord) -> bool:
        """RFC 6762 section 7.1 known answer test: an equal record with more than half our TTL."""
        return self == answer and self.ttl / 2 < answer.ttl


class DNSAddress(DNSRecord):
    """Record holding an IPv4 or IPv6 address."""

    __slots__ = ("_hash", "address", "scope_id")

    def __init__(
        self,
        name: str,
        type_: int,
        class_: int,
        ttl: int,
        address: bytes,
        scope_id: int | None = None,
        created: float | None = None,
    ) -> None:
        self._fast_init(name, type_, class_, ttl, address, scope_id, created or current_time_millis())

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, DNSAddress) and self._eq(other)

    def __hash__(self) -> int:
        """Hash to compare like DNSAddresses."""
        return self._hash

    def __repr__(self) -> str:
        try:
            data = socket.inet_ntop(
                socket.AF_INET6 if _is_v6_address(self.address) else socket.AF_INET,
                self.address,
            )
        except (ValueError, OSError):
            data = str(self.address)
        return self._repr_with(("data", data))

    def write(self, out: DNSOutgoing) -> None:
        out.write_string(self.address)

    def _eq(self, other: DNSAddress) -> bool:
        return (
            self.address == other.address
            and self.scope_id == other.scope_id
            and self._dns_entry_matches(other)
        )

    def _fast_init(
        self,
        name: str,
        type_: _int,
        class_: _int,
        ttl: _int,
        address: bytes,
        scope_id: _int | None,
        created: _float,
    ) -> None:
        """Fast init for reuse."""
        self._fast_init_record(name, type_, class_, ttl, created)
        self.address = address
        self.scope_id = scope_id
        self._hash = hash((self.key, type_, self.class_, address, scope_id))


class DNSHinfo(DNSRecord):
    """HINFO record carrying the host's cpu and os strings."""

    __slots__ = ("_hash", "cpu", "os")

    def __init__(
        self,
        name: str,
        type_: int,
        class_: int,
        ttl: int,
        cpu: str,
        os: str,
        created: float | None = None,
    ) -> None:
        self._fast_init(name, type_, class_, ttl, cpu, os, created or current_time_millis())

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, DNSHinfo) and self._eq(other)

    def __hash__(self) -> int:
        """Hash to compare like DNSHinfo."""
        return self._hash

    def __repr__(self) -> str:
        return self._repr_with(("cpu", self.cpu), ("os", self.os))

    def write(self, out: DNSOutgoing) -> None:
        out.write_character_string(self.cpu.encode("utf-8"))
        out.write_character_string(self.os.encode("utf-8"))

    def _eq(self, other: DNSHinfo) -> bool:
        return self.cpu == other.cpu and self.os == other.os and self._dns_entry_matches(other)

    def _fast_init(
        self, name: str, type_: _int, class_: _int, ttl: _int, cpu: str, os: str, created: _float
    ) -> None:
        """Fast init for reuse."""
        self._fast_init_record(name, type_, class_, ttl, created)
        self.cpu = cpu
        self.os = os
        self._hash = hash((self.key, type_, self.class_, cpu, os))


class DNSNsec(DNSRecord):
    """NSEC record asserting which record types exist for a name."""

    __slots__ = ("_hash", "next_name", "rdtypes")

    def __init__(
        self,
        name: str,
        type_: int,
        class_: int,
        ttl: _int,
        next_name: str,
        rdtypes: list[int],
        created: float | None = None,
    ) -> None:
        self._fast_init(name, type_, class_, ttl, next_name, rdtypes, created or current_time_millis())

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, DNSNsec) and self._eq(other)

    def __hash__(self) -> int:
        """Hash to compare like DNSNSec."""
        return self._hash

    def __repr__(self) -> str:
        covered = "|".join([_type_label(t) for t in self.rdtypes])
        return self._repr_with(("next_name", self.next_name), ("covers", covered))

    def write(self, out: DNSOutgoing) -> None:
        bitmap = bytearray(b"\0" * 32)
        total_octets = 0
        for rdtype in self.rdtypes:
            if rdtype > 255:  # mDNS only supports window 0
                raise ValueError(f"rdtype {rdtype} is too large for NSEC")
            byte = rdtype // 8
            total_octets = byte + 1
            bitmap[byte] |= 0x80 >> (rdtype % 8)
        if total_octets == 0:
            # NSEC must have at least one rdtype
            # Writing an empty bitmap is not allowed
            raise ValueError("NSEC must have at least one rdtype")
        out_bytes = bytes(bitmap[0:total_octets])
        out.write_name(self.next_name)
        out._write_byte(0)  # Always window 0
        out._write_byte(len(out_bytes))
        out.write_string(out_bytes)

    def _eq(self, other: DNSNsec) -> bool:
        return (
            self.next_name == other.next_name
            and self.rdtypes == other.rdtypes
            and self._dns_entry_matches(other)
        )

    def _fast_init(
        self,
        name: str,
        type_: _int,
        class_: _int,
        ttl: _int,
        next_name: str,
        rdtypes: list[_int],
        created: _float,
    ) -> None:
        self._fast_init_record(name, type_, class_, ttl, created)
        self.next_name = next_name
        self.rdtypes = sorted(rdtypes)
        self._hash = hash((self.key, type_, self.class_, next_name, *self.rdtypes))


class DNSPointer(DNSRecord):
    """PTR record naming a service instance."""

    __slots__ = ("_hash", "alias", "alias_key")

    def __init__(
        self,
        name: str,
        type_: int,
        class_: int,
        ttl: int,
        alias: str,
        created: float | None = None,
    ) -> None:
        self._fast_init(name, type_, class_, ttl, alias, created or current_time_millis())

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, DNSPointer) and self._eq(other)

    def __hash__(self) -> int:
        """Hash to compare like DNSPointer."""
        return self._hash

    def __repr__(self) -> str:
        return self._repr_with(("alias", self.alias))

    @property
    def max_size_compressed(self) -> int:
        """Maximum size of the record in the packet assuming the name has been compressed."""
        return (
            _BASE_MAX_SIZE
            + _NAME_COMPRESSION_MIN_SIZE
            + (len(self.alias) - len(self.name))
            + _NAME_COMPRESSION_MIN_SIZE
        )

    def write(self, out: DNSOutgoing) -> None:
        out.write_name(self.alias)

    def _eq(self, other: DNSPointer) -> bool:
        return self.alias_key == other.alias_key and self._dns_entry_matches(other)

    def _fast_init(
        self, name: str, type_: _int, class_: _int, ttl: _int, alias: str, created: _float
    ) -> None:
        self._fast_init_record(name, type_, class_, ttl, created)
        self.alias = alias
        self.alias_key = alias.lower()
        self._hash = hash((self.key, type_, self.class_, self.alias_key))


class DNSService(DNSRecord):
    """SRV record with the target host, port, priority and weight."""

    __slots__ = ("_hash", "port", "priority", "server", "server_key", "weight")

    def __init__(
        self,
        name: str,
        type_: int,
        class_: int,
        ttl: int,
        priority: int,
        weight: int,
        port: int,
        server: str,
        created: float | None = None,
    ) -> None:
        self._fast_init(
            name, type_, class_, ttl, priority, weight, port, server, created or current_time_millis()
        )

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, DNSService) and self._eq(other)

    def __hash__(self) -> int:
        """Hash to compare like DNSService."""
        return self._hash

    def __repr__(self) -> str:
        return self._repr_with(("server", self.server), ("port", str(self.port)))

    def write(self, out: DNSOutgoing) -> None:
        out.write_short(self.priority)
        out.write_short(self.weight)
        out.write_short(self.port)
        out.write_name(self.server)

    def _eq(self, other: DNSService) -> bool:
        return (
            self.priority == other.priority
            and self.weight == other.weight
            and self.port == other.port
            and self.server_key == other.server_key
            and self._dns_entry_matches(other)
        )

    def _fast_init(
        self,
        name: str,
        type_: _int,
        class_: _int,
        ttl: _int,
        priority: _int,
        weight: _int,
        port: _int,
        server: str,
        created: _float,
    ) -> None:
        self._fast_init_record(name, type_, class_, ttl, created)
        self.priority = priority
        self.weight = weight
        self.port = port
        self.server = server
        self.server_key = server.lower()
        self._hash = hash((self.key, type_, self.class_, priority, weight, port, self.server_key))


class DNSText(DNSRecord):
    """TXT record carrying the service properties."""

    __slots__ = ("_hash", "text")

    def __init__(
        self,
        name: str,
        type_: int,
        class_: int,
        ttl: int,
        text: bytes,
        created: float | None = None,
    ) -> None:
        self._fast_init(name, type_, class_, ttl, text, created or current_time_millis())

    def __eq__(self, other: Any) -> bool:
        return isinstance(other, DNSText) and self._eq(other)

    def __hash__(self) -> int:
        """Hash to compare like DNSText."""
        return self._hash

    def __repr__(self) -> str:
        data = f"{len(self.text)} bytes" if len(self.text) > _TEXT_REPR_INLINE_LIMIT else str(self.text)
        return self._repr_with(("data", data))

    def write(self, out: DNSOutgoing) -> None:
        out.write_string(self.text)

    def _eq(self, other: DNSText) -> bool:
        return self.text == other.text and self._dns_entry_matches(other)

    def _fast_init(
        self, name: str, type_: _int, class_: _int, ttl: _int, text: bytes, created: _float
    ) -> None:
        self._fast_init_record(name, type_, class_, ttl, created)
        self.text = text
        self._hash = hash((self.key, type_, self.class_, text))


_DNSRecord = DNSRecord


class DNSRRSet:
    """A set of dns records with a lookup to get the ttl."""

    __slots__ = ("_lookup", "_records")

    def __init__(self, records: list[DNSRecord]) -> None:
        """Create an RRset from records sets."""
        self._records = records
        self._lookup: dict[DNSRecord, DNSRecord] | None = None

    @property
    def lookup(self) -> dict[DNSRecord, DNSRecord]:
        """Return the lookup table."""
        return self._get_lookup()

    def lookup_set(self) -> set[DNSRecord]:
        """Return the lookup table as aset."""
        return set(self._get_lookup())

    def suppresses(self, record: _DNSRecord) -> bool:
        """True when the set holds a match with over half the record's TTL left."""
        lookup = self._get_lookup()
        other = lookup.get(record)
        if other is None:
            return False
        return other.ttl > (record.ttl / 2)

    def _get_lookup(self) -> dict[DNSRecord, DNSRecord]:
        """Return the lookup table, building it if needed."""
        if self._lookup is None:
            # Build the hash table so we can lookup the record ttl
            self._lookup = {record: record for record in self._records}
        return self._lookup
