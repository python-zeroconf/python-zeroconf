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
import errno
import ipaddress
import itertools
import platform
import select
import socket
import struct
import sys
import threading
import time
import warnings
from collections import OrderedDict
from types import TracebackType  # noqa # used in type hints
from typing import Dict, Iterable, List, Optional, Type, Union, cast
from typing import Any, Callable, Set, Tuple  # noqa # used in type hints

import ifaddr

from .const import (  # noqa # import needed for backwards compat
    _BROWSER_BACKOFF_LIMIT,
    _BROWSER_TIME,
    _CACHE_CLEANUP_INTERVAL,
    _CHECK_TIME,
    _CLASSES,
    _CLASS_IN,
    _CLASS_NONE,
    _CLASS_MASK,
    _CLASS_UNIQUE,
    _DNS_HOST_TTL,
    _DNS_OTHER_TTL,
    _DNS_PORT,
    _EXPIRE_FULL_TIME_PERCENT,
    _EXPIRE_REFRESH_TIME_PERCENT,
    _EXPIRE_STALE_TIME_PERCENT,
    _FLAGS_AA,
    _FLAGS_QR_MASK,
    _FLAGS_QR_QUERY,
    _FLAGS_QR_RESPONSE,
    _FLAGS_TC,
    _HAS_ASCII_CONTROL_CHARS,
    _HAS_A_TO_Z,
    _HAS_ONLY_A_TO_Z_NUM_HYPHEN,
    _HAS_ONLY_A_TO_Z_NUM_HYPHEN_UNDERSCORE,
    _IPPROTO_IPV6,
    _LISTENER_TIME,
    _LOCAL_TRAILER,
    _MAX_MSG_ABSOLUTE,
    _MAX_MSG_TYPICAL,
    _MDNS_ADDR,
    _MDNS_ADDR6,
    _MDNS_ADDR6_BYTES,
    _MDNS_ADDR_BYTES,
    _MDNS_PORT,
    _NONTCP_PROTOCOL_LOCAL_TRAILER,
    _REGISTER_TIME,
    _SERVICE_TYPE_ENUMERATION_NAME,
    _TCP_PROTOCOL_LOCAL_TRAILER,
    _TYPES,
    _TYPE_A,
    _TYPE_AAAA,
    _TYPE_ANY,
    _TYPE_CNAME,
    _TYPE_HINFO,
    _TYPE_PTR,
    _TYPE_SOA,
    _TYPE_SRV,
    _TYPE_TXT,
    _UNREGISTER_TIME,
)
from .exceptions import (
    AbstractMethodException,
    BadTypeInNameException,
    Error,
    IncomingDecodeError,
    NamePartTooLongException,
    NonUniqueNameException,
    ServiceNameAlreadyRegistered,
)
from .logger import QuietLogger, log

__author__ = 'Paul Scott-Murphy, William McBrine'
__maintainer__ = 'Jakub Stasiak <jakub@stasiak.at>'
__version__ = '0.31.0'
__license__ = 'LGPL'


__all__ = [
    "__version__",
    "Zeroconf",
    "ServiceInfo",
    "ServiceBrowser",
    "ServiceListener",
    "Error",
    "InterfaceChoice",
    "ServiceStateChange",
    "IPVersion",
]

if sys.version_info <= (3, 6):
    raise ImportError(
        '''
Python version > 3.6 required for python-zeroconf.
If you need support for Python 2 or Python 3.3-3.4 please use version 19.1
If you need support for Python 3.5 please use version 0.28.0
    '''
    )


int2byte = struct.Struct(">B").pack


@enum.unique
class InterfaceChoice(enum.Enum):
    Default = 1
    All = 2


InterfacesType = Union[List[Union[str, int, Tuple[Tuple[str, int, int], int]]], InterfaceChoice]


@enum.unique
class ServiceStateChange(enum.Enum):
    Added = 1
    Removed = 2
    Updated = 3


@enum.unique
class IPVersion(enum.Enum):
    V4Only = 1
    V6Only = 2
    All = 3


# utility functions


def current_time_millis() -> float:
    """Current system time in milliseconds"""
    return time.time() * 1000


def millis_to_seconds(millis: float) -> float:
    """Convert milliseconds to seconds."""
    return millis / 1000.0


def _is_v6_address(addr: bytes) -> bool:
    return len(addr) == 16


def _encode_address(address: str) -> bytes:
    is_ipv6 = ':' in address
    address_family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    return socket.inet_pton(address_family, address)


def service_type_name(type_: str, *, strict: bool = True) -> str:  # pylint: disable=too-many-branches
    """
    Validate a fully qualified service name, instance or subtype. [rfc6763]

    Returns fully qualified service name.

    Domain names used by mDNS-SD take the following forms:

                   <sn> . <_tcp|_udp> . local.
      <Instance> . <sn> . <_tcp|_udp> . local.
      <sub>._sub . <sn> . <_tcp|_udp> . local.

    1) must end with 'local.'

      This is true because we are implementing mDNS and since the 'm' means
      multi-cast, the 'local.' domain is mandatory.

    2) local is preceded with either '_udp.' or '_tcp.' unless
       strict is False

    3) service name <sn> precedes <_tcp|_udp> unless
       strict is False

      The rules for Service Names [RFC6335] state that they may be no more
      than fifteen characters long (not counting the mandatory underscore),
      consisting of only letters, digits, and hyphens, must begin and end
      with a letter or digit, must not contain consecutive hyphens, and
      must contain at least one letter.

    The instance name <Instance> and sub type <sub> may be up to 63 bytes.

    The portion of the Service Instance Name is a user-
    friendly name consisting of arbitrary Net-Unicode text [RFC5198]. It
    MUST NOT contain ASCII control characters (byte values 0x00-0x1F and
    0x7F) [RFC20] but otherwise is allowed to contain any characters,
    without restriction, including spaces, uppercase, lowercase,
    punctuation -- including dots -- accented characters, non-Roman text,
    and anything else that may be represented using Net-Unicode.

    :param type_: Type, SubType or service name to validate
    :return: fully qualified service name (eg: _http._tcp.local.)
    """

    if type_.endswith((_TCP_PROTOCOL_LOCAL_TRAILER, _NONTCP_PROTOCOL_LOCAL_TRAILER)):
        remaining = type_[: -len(_TCP_PROTOCOL_LOCAL_TRAILER)].split('.')
        trailer = type_[-len(_TCP_PROTOCOL_LOCAL_TRAILER) :]
        has_protocol = True
    elif strict:
        raise BadTypeInNameException(
            "Type '%s' must end with '%s' or '%s'"
            % (type_, _TCP_PROTOCOL_LOCAL_TRAILER, _NONTCP_PROTOCOL_LOCAL_TRAILER)
        )
    elif type_.endswith(_LOCAL_TRAILER):
        remaining = type_[: -len(_LOCAL_TRAILER)].split('.')
        trailer = type_[-len(_LOCAL_TRAILER) + 1 :]
        has_protocol = False
    else:
        raise BadTypeInNameException("Type '%s' must end with '%s'" % (type_, _LOCAL_TRAILER))

    if strict or has_protocol:
        service_name = remaining.pop()
        if not service_name:
            raise BadTypeInNameException("No Service name found")

        if len(remaining) == 1 and len(remaining[0]) == 0:
            raise BadTypeInNameException("Type '%s' must not start with '.'" % type_)

        if service_name[0] != '_':
            raise BadTypeInNameException("Service name (%s) must start with '_'" % service_name)

        test_service_name = service_name[1:]

        if len(test_service_name) > 15:
            raise BadTypeInNameException("Service name (%s) must be <= 15 bytes" % test_service_name)

        if '--' in test_service_name:
            raise BadTypeInNameException("Service name (%s) must not contain '--'" % test_service_name)

        if '-' in (test_service_name[0], test_service_name[-1]):
            raise BadTypeInNameException(
                "Service name (%s) may not start or end with '-'" % test_service_name
            )

        if not _HAS_A_TO_Z.search(test_service_name):
            raise BadTypeInNameException(
                "Service name (%s) must contain at least one letter (eg: 'A-Z')" % test_service_name
            )

        allowed_characters_re = (
            _HAS_ONLY_A_TO_Z_NUM_HYPHEN if strict else _HAS_ONLY_A_TO_Z_NUM_HYPHEN_UNDERSCORE
        )

        if not allowed_characters_re.search(test_service_name):
            raise BadTypeInNameException(
                "Service name (%s) must contain only these characters: "
                "A-Z, a-z, 0-9, hyphen ('-')%s" % (test_service_name, "" if strict else ", underscore ('_')")
            )
    else:
        service_name = ''

    if remaining and remaining[-1] == '_sub':
        remaining.pop()
        if len(remaining) == 0 or len(remaining[0]) == 0:
            raise BadTypeInNameException("_sub requires a subtype name")

    if len(remaining) > 1:
        remaining = ['.'.join(remaining)]

    if remaining:
        length = len(remaining[0].encode('utf-8'))
        if length > 63:
            raise BadTypeInNameException("Too long: '%s'" % remaining[0])

        if _HAS_ASCII_CONTROL_CHARS.search(remaining[0]):
            raise BadTypeInNameException(
                "Ascii control character 0x00-0x1F and 0x7F illegal in '%s'" % remaining[0]
            )

    return service_name + trailer


def instance_name_from_service_info(info: "ServiceInfo") -> str:
    """Calculate the instance name from the ServiceInfo."""
    # This is kind of funky because of the subtype based tests
    # need to make subtypes a first class citizen
    service_name = service_type_name(info.name)
    if not info.type.endswith(service_name):
        raise BadTypeInNameException
    return info.name[: -len(service_name) - 1]


# implementation classes


class DNSEntry:

    """A DNS entry"""

    def __init__(self, name: str, type_: int, class_: int) -> None:
        self.key = name.lower()
        self.name = name
        self.type = type_
        self.class_ = class_ & _CLASS_MASK
        self.unique = (class_ & _CLASS_UNIQUE) != 0

    def __eq__(self, other: Any) -> bool:
        """Equality test on key (lowercase name), type, and class"""
        return (
            self.key == other.key
            and self.type == other.type
            and self.class_ == other.class_
            and isinstance(other, DNSEntry)
        )

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
        result = "%s[%s,%s" % (hdr, self.get_type(self.type), self.get_class_(self.class_))
        if self.unique:
            result += "-unique,"
        else:
            result += ","
        result += self.name
        if other is not None:
            result += "]=%s" % cast(Any, other)
        else:
            result += "]"
        return result


class DNSQuestion(DNSEntry):

    """A DNS question entry"""

    def __init__(self, name: str, type_: int, class_: int) -> None:
        DNSEntry.__init__(self, name, type_, class_)

    def answered_by(self, rec: 'DNSRecord') -> bool:
        """Returns true if the question is answered by the record"""
        return (
            self.class_ == rec.class_
            and (self.type == rec.type or self.type == _TYPE_ANY)
            and self.name == rec.name
        )

    def __repr__(self) -> str:
        """String representation"""
        return DNSEntry.entry_to_string(self, "question", None)


class DNSRecord(DNSEntry):

    """A DNS record - like a DNS entry, but has a TTL"""

    # TODO: Switch to just int ttl
    def __init__(self, name: str, type_: int, class_: int, ttl: Union[float, int]) -> None:
        DNSEntry.__init__(self, name, type_, class_)
        self.ttl = ttl
        self.created = current_time_millis()
        self._expiration_time = self.get_expiration_time(_EXPIRE_FULL_TIME_PERCENT)
        self._stale_time = self.get_expiration_time(_EXPIRE_STALE_TIME_PERCENT)

    def __eq__(self, other: Any) -> bool:  # pylint: disable=no-self-use
        """Abstract method"""
        raise AbstractMethodException

    def suppressed_by(self, msg: 'DNSIncoming') -> bool:
        """Returns true if any answer in a message can suffice for the
        information held in this record."""
        for record in msg.answers:
            if self.suppressed_by_answer(record):
                return True
        return False

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
        return max(0, millis_to_seconds(self._expiration_time - now))

    def is_expired(self, now: float) -> bool:
        """Returns true if this record has expired."""
        return self._expiration_time <= now

    def is_stale(self, now: float) -> bool:
        """Returns true if this record is at least half way expired."""
        return self._stale_time <= now

    def reset_ttl(self, other: 'DNSRecord') -> None:
        """Sets this record's TTL and created time to that of
        another record."""
        self.created = other.created
        self.ttl = other.ttl
        self._expiration_time = self.get_expiration_time(_EXPIRE_FULL_TIME_PERCENT)
        self._stale_time = self.get_expiration_time(_EXPIRE_STALE_TIME_PERCENT)

    def write(self, out: 'DNSOutgoing') -> None:  # pylint: disable=no-self-use
        """Abstract method"""
        raise AbstractMethodException

    def to_string(self, other: Union[bytes, str]) -> str:
        """String representation with additional information"""
        arg = "%s/%s,%s" % (self.ttl, int(self.get_remaining_ttl(current_time_millis())), cast(Any, other))
        return DNSEntry.entry_to_string(self, "record", arg)


class DNSAddress(DNSRecord):

    """A DNS address record"""

    def __init__(self, name: str, type_: int, class_: int, ttl: int, address: bytes) -> None:
        DNSRecord.__init__(self, name, type_, class_, ttl)
        self.address = address

    def write(self, out: 'DNSOutgoing') -> None:
        """Used in constructing an outgoing packet"""
        out.write_string(self.address)

    def __eq__(self, other: Any) -> bool:
        """Tests equality on address"""
        return (
            isinstance(other, DNSAddress) and DNSEntry.__eq__(self, other) and self.address == other.address
        )

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

    def __init__(self, name: str, type_: int, class_: int, ttl: int, cpu: str, os: str) -> None:
        DNSRecord.__init__(self, name, type_, class_, ttl)
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
            and DNSEntry.__eq__(self, other)
            and self.cpu == other.cpu
            and self.os == other.os
        )

    def __repr__(self) -> str:
        """String representation"""
        return self.to_string(self.cpu + " " + self.os)


class DNSPointer(DNSRecord):

    """A DNS pointer record"""

    def __init__(self, name: str, type_: int, class_: int, ttl: int, alias: str) -> None:
        DNSRecord.__init__(self, name, type_, class_, ttl)
        self.alias = alias

    def write(self, out: 'DNSOutgoing') -> None:
        """Used in constructing an outgoing packet"""
        out.write_name(self.alias)

    def __eq__(self, other: Any) -> bool:
        """Tests equality on alias"""
        return isinstance(other, DNSPointer) and self.alias == other.alias and DNSEntry.__eq__(self, other)

    def __repr__(self) -> str:
        """String representation"""
        return self.to_string(self.alias)


class DNSText(DNSRecord):

    """A DNS text record"""

    def __init__(self, name: str, type_: int, class_: int, ttl: int, text: bytes) -> None:
        assert isinstance(text, (bytes, type(None)))
        DNSRecord.__init__(self, name, type_, class_, ttl)
        self.text = text

    def write(self, out: 'DNSOutgoing') -> None:
        """Used in constructing an outgoing packet"""
        out.write_string(self.text)

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
    ) -> None:
        DNSRecord.__init__(self, name, type_, class_, ttl)
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

    def __repr__(self) -> str:
        """String representation"""
        return self.to_string("%s:%s" % (self.server, self.port))


class DNSMessage:
    """A base class for DNS messages."""

    def __init__(self, flags: int) -> None:
        """Construct a DNS message."""
        self.flags = flags

    def is_query(self) -> bool:
        """Returns true if this is a query."""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_QUERY

    def is_response(self) -> bool:
        """Returns true if this is a response."""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_RESPONSE


class DNSIncoming(DNSMessage, QuietLogger):

    """Object representation of an incoming DNS packet"""

    def __init__(self, data: bytes) -> None:
        """Constructor from string holding bytes of packet"""
        super().__init__(0)
        self.offset = 0
        self.data = data
        self.questions = []  # type: List[DNSQuestion]
        self.answers = []  # type: List[DNSRecord]
        self.id = 0
        self.num_questions = 0
        self.num_answers = 0
        self.num_authorities = 0
        self.num_additionals = 0
        self.valid = False

        try:
            self.read_header()
            self.read_questions()
            self.read_others()
            self.valid = True

        except (IndexError, struct.error, IncomingDecodeError):
            self.log_exception_warning('Choked at offset %d while unpacking %r', self.offset, data)

    def __repr__(self) -> str:
        return '<DNSIncoming:{%s}>' % ', '.join(
            [
                'id=%s' % self.id,
                'flags=%s' % self.flags,
                'n_q=%s' % self.num_questions,
                'n_ans=%s' % self.num_answers,
                'n_auth=%s' % self.num_authorities,
                'n_add=%s' % self.num_additionals,
                'questions=%s' % self.questions,
                'answers=%s' % self.answers,
            ]
        )

    def unpack(self, format_: bytes) -> tuple:
        length = struct.calcsize(format_)
        info = struct.unpack(format_, self.data[self.offset : self.offset + length])
        self.offset += length
        return info

    def read_header(self) -> None:
        """Reads header portion of packet"""
        (
            self.id,
            self.flags,
            self.num_questions,
            self.num_answers,
            self.num_authorities,
            self.num_additionals,
        ) = self.unpack(b'!6H')

    def read_questions(self) -> None:
        """Reads questions section of packet"""
        for _ in range(self.num_questions):
            name = self.read_name()
            type_, class_ = self.unpack(b'!HH')

            question = DNSQuestion(name, type_, class_)
            self.questions.append(question)

    # def read_int(self):
    #     """Reads an integer from the packet"""
    #     return self.unpack(b'!I')[0]

    def read_character_string(self) -> bytes:
        """Reads a character string from the packet"""
        length = self.data[self.offset]
        self.offset += 1
        return self.read_string(length)

    def read_string(self, length: int) -> bytes:
        """Reads a string of a given length from the packet"""
        info = self.data[self.offset : self.offset + length]
        self.offset += length
        return info

    def read_unsigned_short(self) -> int:
        """Reads an unsigned short from the packet"""
        return cast(int, self.unpack(b'!H')[0])

    def read_others(self) -> None:
        """Reads the answers, authorities and additionals section of the
        packet"""
        n = self.num_answers + self.num_authorities + self.num_additionals
        for _ in range(n):
            domain = self.read_name()
            type_, class_, ttl, length = self.unpack(b'!HHiH')

            rec = None  # type: Optional[DNSRecord]
            if type_ == _TYPE_A:
                rec = DNSAddress(domain, type_, class_, ttl, self.read_string(4))
            elif type_ in (_TYPE_CNAME, _TYPE_PTR):
                rec = DNSPointer(domain, type_, class_, ttl, self.read_name())
            elif type_ == _TYPE_TXT:
                rec = DNSText(domain, type_, class_, ttl, self.read_string(length))
            elif type_ == _TYPE_SRV:
                rec = DNSService(
                    domain,
                    type_,
                    class_,
                    ttl,
                    self.read_unsigned_short(),
                    self.read_unsigned_short(),
                    self.read_unsigned_short(),
                    self.read_name(),
                )
            elif type_ == _TYPE_HINFO:
                rec = DNSHinfo(
                    domain,
                    type_,
                    class_,
                    ttl,
                    self.read_character_string().decode('utf-8'),
                    self.read_character_string().decode('utf-8'),
                )
            elif type_ == _TYPE_AAAA:
                rec = DNSAddress(domain, type_, class_, ttl, self.read_string(16))
            else:
                # Try to ignore types we don't know about
                # Skip the payload for the resource record so the next
                # records can be parsed correctly
                self.offset += length

            if rec is not None:
                self.answers.append(rec)

    def read_utf(self, offset: int, length: int) -> str:
        """Reads a UTF-8 string of a given length from the packet"""
        return str(self.data[offset : offset + length], 'utf-8', 'replace')

    def read_name(self) -> str:
        """Reads a domain name from the packet"""
        result = ''
        off = self.offset
        next_ = -1
        first = off

        while True:
            length = self.data[off]
            off += 1
            if length == 0:
                break
            t = length & 0xC0
            if t == 0x00:
                result += self.read_utf(off, length) + '.'
                off += length
            elif t == 0xC0:
                if next_ < 0:
                    next_ = off + 1
                off = ((length & 0x3F) << 8) | self.data[off]
                if off >= first:
                    raise IncomingDecodeError("Bad domain name (circular) at %s" % (off,))
                first = off
            else:
                raise IncomingDecodeError("Bad domain name at %s" % (off,))

        if next_ >= 0:
            self.offset = next_
        else:
            self.offset = off

        return result


class DNSOutgoing(DNSMessage):

    """Object representation of an outgoing packet"""

    def __init__(self, flags: int, multicast: bool = True) -> None:
        super().__init__(flags)
        self.finished = False
        self.id = 0
        self.multicast = multicast
        self.packets_data = []  # type: List[bytes]

        # these 3 are per-packet -- see also reset_for_next_packet()
        self.names = {}  # type: Dict[str, int]
        self.data = []  # type: List[bytes]
        self.size = 12
        self.allow_long = True

        self.state = self.State.init

        self.questions = []  # type: List[DNSQuestion]
        self.answers = []  # type: List[Tuple[DNSRecord, float]]
        self.authorities = []  # type: List[DNSPointer]
        self.additionals = []  # type: List[DNSRecord]

    def reset_for_next_packet(self) -> None:
        self.names = {}
        self.data = []
        self.size = 12
        self.allow_long = True

    def __repr__(self) -> str:
        return '<DNSOutgoing:{%s}>' % ', '.join(
            [
                'multicast=%s' % self.multicast,
                'flags=%s' % self.flags,
                'questions=%s' % self.questions,
                'answers=%s' % self.answers,
                'authorities=%s' % self.authorities,
                'additionals=%s' % self.additionals,
            ]
        )

    class State(enum.Enum):
        init = 0
        finished = 1

    def add_question(self, record: DNSQuestion) -> None:
        """Adds a question"""
        self.questions.append(record)

    def add_answer(self, inp: DNSIncoming, record: DNSRecord) -> None:
        """Adds an answer"""
        if not record.suppressed_by(inp):
            self.add_answer_at_time(record, 0)

    def add_answer_at_time(self, record: Optional[DNSRecord], now: Union[float, int]) -> None:
        """Adds an answer if it does not expire by a certain time"""
        if record is not None:
            if now == 0 or not record.is_expired(now):
                self.answers.append((record, now))

    def add_authorative_answer(self, record: DNSPointer) -> None:
        """Adds an authoritative answer"""
        self.authorities.append(record)

    def add_additional_answer(self, record: DNSRecord) -> None:
        """Adds an additional answer

        From: RFC 6763, DNS-Based Service Discovery, February 2013

        12.  DNS Additional Record Generation

           DNS has an efficiency feature whereby a DNS server may place
           additional records in the additional section of the DNS message.
           These additional records are records that the client did not
           explicitly request, but the server has reasonable grounds to expect
           that the client might request them shortly, so including them can
           save the client from having to issue additional queries.

           This section recommends which additional records SHOULD be generated
           to improve network efficiency, for both Unicast and Multicast DNS-SD
           responses.

        12.1.  PTR Records

           When including a DNS-SD Service Instance Enumeration or Selective
           Instance Enumeration (subtype) PTR record in a response packet, the
           server/responder SHOULD include the following additional records:

           o  The SRV record(s) named in the PTR rdata.
           o  The TXT record(s) named in the PTR rdata.
           o  All address records (type "A" and "AAAA") named in the SRV rdata.

        12.2.  SRV Records

           When including an SRV record in a response packet, the
           server/responder SHOULD include the following additional records:

           o  All address records (type "A" and "AAAA") named in the SRV rdata.

        """
        self.additionals.append(record)

    def add_question_or_one_cache(
        self, cache: "DNSCache", now: float, name: str, type_: int, class_: int
    ) -> None:
        """Add a question if it is not already cached."""
        cached_entry = cache.get_by_details(name, type_, class_)
        if not cached_entry:
            self.add_question(DNSQuestion(name, type_, class_))
        else:
            self.add_answer_at_time(cached_entry, now)

    def add_question_or_all_cache(
        self, cache: "DNSCache", now: float, name: str, type_: int, class_: int
    ) -> None:
        """Add a question if it is not already cached.
        This is currently only used for IPv6 addresses.
        """
        cached_entries = cache.get_all_by_details(name, type_, class_)
        if not cached_entries:
            self.add_question(DNSQuestion(name, type_, class_))
            return
        for cached_entry in cached_entries:
            self.add_answer_at_time(cached_entry, now)

    def pack(self, format_: Union[bytes, str], value: Any) -> None:
        self.data.append(struct.pack(format_, value))
        self.size += struct.calcsize(format_)

    def write_byte(self, value: int) -> None:
        """Writes a single byte to the packet"""
        self.pack(b'!c', int2byte(value))

    def insert_short_at_start(self, value: int) -> None:
        """Inserts an unsigned short at the start of the packet"""
        self.data.insert(0, struct.pack(b'!H', value))

    def replace_short(self, index: int, value: int) -> None:
        """Replaces an unsigned short in a certain position in the packet"""
        self.data[index] = struct.pack(b'!H', value)

    def write_short(self, value: int) -> None:
        """Writes an unsigned short to the packet"""
        self.pack(b'!H', value)

    def write_int(self, value: Union[float, int]) -> None:
        """Writes an unsigned integer to the packet"""
        self.pack(b'!I', int(value))

    def write_string(self, value: bytes) -> None:
        """Writes a string to the packet"""
        assert isinstance(value, bytes)
        self.data.append(value)
        self.size += len(value)

    def write_utf(self, s: str) -> None:
        """Writes a UTF-8 string of a given length to the packet"""
        utfstr = s.encode('utf-8')
        length = len(utfstr)
        if length > 64:
            raise NamePartTooLongException
        self.write_byte(length)
        self.write_string(utfstr)

    def write_character_string(self, value: bytes) -> None:
        assert isinstance(value, bytes)
        length = len(value)
        if length > 256:
            raise NamePartTooLongException
        self.write_byte(length)
        self.write_string(value)

    def write_name(self, name: str) -> None:
        """
        Write names to packet

        18.14. Name Compression

        When generating Multicast DNS messages, implementations SHOULD use
        name compression wherever possible to compress the names of resource
        records, by replacing some or all of the resource record name with a
        compact two-byte reference to an appearance of that data somewhere
        earlier in the message [RFC1035].
        """

        # split name into each label
        parts = name.split('.')
        if not parts[-1]:
            parts.pop()

        # construct each suffix
        name_suffices = ['.'.join(parts[i:]) for i in range(len(parts))]

        # look for an existing name or suffix
        for count, sub_name in enumerate(name_suffices):
            if sub_name in self.names:
                break
        else:
            count = len(name_suffices)

        # note the new names we are saving into the packet
        name_length = len(name.encode('utf-8'))
        for suffix in name_suffices[:count]:
            self.names[suffix] = self.size + name_length - len(suffix.encode('utf-8')) - 1

        # write the new names out.
        for part in parts[:count]:
            self.write_utf(part)

        # if we wrote part of the name, create a pointer to the rest
        if count != len(name_suffices):
            # Found substring in packet, create pointer
            index = self.names[name_suffices[count]]
            self.write_byte((index >> 8) | 0xC0)
            self.write_byte(index & 0xFF)
        else:
            # this is the end of a name
            self.write_byte(0)

    def write_question(self, question: DNSQuestion) -> bool:
        """Writes a question to the packet"""
        start_data_length, start_size = len(self.data), self.size
        self.write_name(question.name)
        self.write_short(question.type)
        self.write_short(question.class_)
        return self._check_data_limit_or_rollback(start_data_length, start_size)

    def write_record(self, record: DNSRecord, now: float) -> bool:
        """Writes a record (answer, authoritative answer, additional) to
        the packet.  Returns True on success, or False if we did not (either
        because the packet was already finished or because the record does
        not fit."""
        if self.state == self.State.finished:
            return False

        start_data_length, start_size = len(self.data), self.size
        self.write_name(record.name)
        self.write_short(record.type)
        if record.unique and self.multicast:
            self.write_short(record.class_ | _CLASS_UNIQUE)
        else:
            self.write_short(record.class_)
        if now == 0:
            self.write_int(record.ttl)
        else:
            self.write_int(record.get_remaining_ttl(now))
        index = len(self.data)

        self.write_short(0)  # Will get replaced with the actual size
        record.write(self)
        # Adjust size for the short we will write before this record
        length = sum((len(d) for d in self.data[index + 1 :]))
        # Here we replace the 0 length short we wrote
        # before with the actual length
        self.replace_short(index, length)
        return self._check_data_limit_or_rollback(start_data_length, start_size)

    def _check_data_limit_or_rollback(self, start_data_length: int, start_size: int) -> bool:
        """Check data limit, if we go over, then rollback and return False."""
        len_limit = _MAX_MSG_ABSOLUTE if self.allow_long else _MAX_MSG_TYPICAL
        self.allow_long = False

        if self.size <= len_limit:
            return True

        log.debug("Reached data limit (size=%d) > (limit=%d) - rolling back", self.size, len_limit)

        while len(self.data) > start_data_length:
            self.data.pop()
        self.size = start_size

        rollback_names = [name for name, idx in self.names.items() if idx >= start_size]
        for name in rollback_names:
            del self.names[name]
        return False

    def packet(self) -> bytes:
        """Returns a bytestring containing the first packet's bytes.

        Generally, you want to use packets() in case the response
        does not fit in a single packet, but this exists for
        backward compatibility."""
        packets = self.packets()
        if len(packets) == 0:
            return b''
        if len(packets[0]) > _MAX_MSG_ABSOLUTE:
            QuietLogger.log_warning_once(
                "Created over-sized packet (%d bytes) %r", len(packets[0]), packets[0]
            )
        return packets[0]

    def _write_questions_from_offset(self, questions_offset: int) -> int:
        questions_written = 0
        for question in self.questions[questions_offset:]:
            if not self.write_question(question):
                break
            questions_written += 1
        return questions_written

    def _write_answers_from_offset(self, answer_offset: int) -> int:
        answers_written = 0
        for answer, time_ in self.answers[answer_offset:]:
            if not self.write_record(answer, time_):
                break
            answers_written += 1
        return answers_written

    def _write_authorities_from_offset(self, authority_offset: int) -> int:
        authorities_written = 0
        for authority in self.authorities[authority_offset:]:
            if not self.write_record(authority, 0):
                break
            authorities_written += 1
        return authorities_written

    def _write_additionals_from_offset(self, additional_offset: int) -> int:
        additionals_written = 0
        for additional in self.additionals[additional_offset:]:
            if not self.write_record(additional, 0):
                break
            additionals_written += 1
        return additionals_written

    def _has_more_to_add(
        self, questions_offset: int, answer_offset: int, authority_offset: int, additional_offset: int
    ) -> bool:
        """Check if all questions, answers, authority, and additionals have been written to the packet."""
        return (
            questions_offset < len(self.questions)
            or answer_offset < len(self.answers)
            or authority_offset < len(self.authorities)
            or additional_offset < len(self.additionals)
        )

    def packets(self) -> List[bytes]:
        """Returns a list of bytestrings containing the packets' bytes

        No further parts should be added to the packet once this
        is done.  The packets are each restricted to _MAX_MSG_TYPICAL
        or less in length, except for the case of a single answer which
        will be written out to a single oversized packet no more than
        _MAX_MSG_ABSOLUTE in length (and hence will be subject to IP
        fragmentation potentially)."""

        if self.state == self.State.finished:
            return self.packets_data

        questions_offset = 0
        answer_offset = 0
        authority_offset = 0
        additional_offset = 0
        # we have to at least write out the question
        first_time = True

        while first_time or self._has_more_to_add(
            questions_offset, answer_offset, authority_offset, additional_offset
        ):
            first_time = False
            log.debug(
                "offsets = questions=%d, answers=%d, authorities=%d, additionals=%d",
                questions_offset,
                answer_offset,
                authority_offset,
                additional_offset,
            )
            log.debug(
                "lengths = questions=%d, answers=%d, authorities=%d, additionals=%d",
                len(self.questions),
                len(self.answers),
                len(self.authorities),
                len(self.additionals),
            )

            questions_written = self._write_questions_from_offset(questions_offset)
            answers_written = self._write_answers_from_offset(answer_offset)
            authorities_written = self._write_authorities_from_offset(authority_offset)
            additionals_written = self._write_additionals_from_offset(additional_offset)

            self.insert_short_at_start(additionals_written)
            self.insert_short_at_start(authorities_written)
            self.insert_short_at_start(answers_written)
            self.insert_short_at_start(questions_written)

            questions_offset += questions_written
            answer_offset += answers_written
            authority_offset += authorities_written
            additional_offset += additionals_written
            log.debug(
                "now offsets = questions=%d, answers=%d, authorities=%d, additionals=%d",
                questions_offset,
                answer_offset,
                authority_offset,
                additional_offset,
            )

            if self.is_query() and self._has_more_to_add(
                questions_offset, answer_offset, authority_offset, additional_offset
            ):
                # https://datatracker.ietf.org/doc/html/rfc6762#section-7.2
                log.debug("Setting TC flag")
                self.insert_short_at_start(self.flags | _FLAGS_TC)
            else:
                self.insert_short_at_start(self.flags)

            if self.multicast:
                self.insert_short_at_start(0)
            else:
                self.insert_short_at_start(self.id)

            self.packets_data.append(b''.join(self.data))
            self.reset_for_next_packet()

            if (questions_written + answers_written + authorities_written + additionals_written) == 0 and (
                len(self.questions) + len(self.answers) + len(self.authorities) + len(self.additionals)
            ) > 0:
                log.warning("packets() made no progress adding records; returning")
                break
        self.state = self.State.finished
        return self.packets_data


class DNSCache:

    """A cache of DNS entries"""

    def __init__(self) -> None:
        self.cache = {}  # type: Dict[str, List[DNSRecord]]
        self.service_cache = {}  # type: Dict[str, List[DNSRecord]]

    def add(self, entry: DNSRecord) -> None:
        """Adds an entry"""
        # Insert last in list, get will return newest entry
        # iteration will result in last update winning
        self.cache.setdefault(entry.key, []).append(entry)
        if isinstance(entry, DNSService):
            self.service_cache.setdefault(entry.server, []).append(entry)

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
            cache[key].remove(entry)
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
        return self.service_cache.get(server, [])[:]

    def entries_with_name(self, name: str) -> List[DNSRecord]:
        """Returns a list of entries whose key matches the name."""
        return self.cache.get(name.lower(), [])[:]

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


class Engine(threading.Thread):

    """An engine wraps read access to sockets, allowing objects that
    need to receive data from sockets to be called back when the
    sockets are ready.

    A reader needs a handle_read() method, which is called when the socket
    it is interested in is ready for reading.

    Writers are not implemented here, because we only send short
    packets.
    """

    def __init__(self, zc: 'Zeroconf') -> None:
        threading.Thread.__init__(self)
        self.daemon = True
        self.zc = zc
        self.readers = {}  # type: Dict[socket.socket, Listener]
        self.timeout = 5
        self.condition = threading.Condition()
        self.socketpair = socket.socketpair()
        self._last_cache_cleanup = 0.0
        self.name = "zeroconf-Engine-%s" % (getattr(self, 'native_id', self.ident),)

    def run(self) -> None:
        while not self.zc.done:
            try:
                rr, _wr, _er = select.select([*self.readers.keys(), self.socketpair[0]], [], [], self.timeout)

                if self.zc.done:
                    return

                for socket_ in rr:
                    reader = self.readers.get(socket_)
                    if reader:
                        reader.handle_read(socket_)

                if self.socketpair[0] in rr:
                    # Clear the socket's buffer
                    self.socketpair[0].recv(128)

            except (select.error, socket.error) as e:
                # If the socket was closed by another thread, during
                # shutdown, ignore it and exit
                if e.args[0] not in (errno.EBADF, errno.ENOTCONN) or not self.zc.done:
                    raise

            now = current_time_millis()
            if now - self._last_cache_cleanup >= _CACHE_CLEANUP_INTERVAL:
                self._last_cache_cleanup = now
                self.zc.record_manager.updates(now, list(self.zc.cache.expire(now)))
                self.zc.record_manager.updates_complete()

        self.socketpair[0].close()
        self.socketpair[1].close()

    def _notify(self) -> None:
        self.condition.notify()
        try:
            self.socketpair[1].send(b'x')
        except socket.error:
            # The socketpair may already be closed during shutdown, ignore it
            if not self.zc.done:
                raise

    def add_reader(self, reader: 'Listener', socket_: socket.socket) -> None:
        with self.condition:
            self.readers[socket_] = reader
            self._notify()

    def del_reader(self, socket_: socket.socket) -> None:
        with self.condition:
            del self.readers[socket_]
            self._notify()


class Listener(QuietLogger):

    """A Listener is used by this module to listen on the multicast
    group to which DNS messages are sent, allowing the implementation
    to cache information as it arrives.

    It requires registration with an Engine object in order to have
    the read() method called when a socket is available for reading."""

    def __init__(self, zc: 'Zeroconf') -> None:
        self.zc = zc
        self.data = None  # type: Optional[bytes]

    def handle_read(self, socket_: socket.socket) -> None:
        try:
            data, (addr, port, *_v6) = socket_.recvfrom(_MAX_MSG_ABSOLUTE)
        except Exception:  # pylint: disable=broad-except
            self.log_exception_warning('Error reading from socket %d', socket_.fileno())
            return

        if self.data == data:
            log.debug(
                'Ignoring duplicate message received from %r:%r (socket %d) (%d bytes) as [%r]',
                addr,
                port,
                socket_.fileno(),
                len(data),
                data,
            )
            return

        self.data = data
        msg = DNSIncoming(data)
        if msg.valid:
            log.debug(
                'Received from %r:%r (socket %d): %r (%d bytes) as [%r]',
                addr,
                port,
                socket_.fileno(),
                msg,
                len(data),
                data,
            )
        else:
            log.debug(
                'Received from %r:%r (socket %d): (%d bytes) [%r]',
                addr,
                port,
                socket_.fileno(),
                len(data),
                data,
            )

        if not msg.valid:
            pass

        elif msg.is_query():
            # Always multicast responses
            if port == _MDNS_PORT:
                self.zc.handle_query(msg, None, _MDNS_PORT)

            # If it's not a multicast query, reply via unicast
            # and multicast
            elif port == _DNS_PORT:
                self.zc.handle_query(msg, addr, port)
                self.zc.handle_query(msg, None, _MDNS_PORT)

        else:
            self.zc.handle_response(msg)


class Signal:
    def __init__(self) -> None:
        self._handlers = []  # type: List[Callable[..., None]]

    def fire(self, **kwargs: Any) -> None:
        for h in list(self._handlers):
            h(**kwargs)

    @property
    def registration_interface(self) -> 'SignalRegistrationInterface':
        return SignalRegistrationInterface(self._handlers)


class SignalRegistrationInterface:
    def __init__(self, handlers: List[Callable[..., None]]) -> None:
        self._handlers = handlers

    def register_handler(self, handler: Callable[..., None]) -> 'SignalRegistrationInterface':
        self._handlers.append(handler)
        return self

    def unregister_handler(self, handler: Callable[..., None]) -> 'SignalRegistrationInterface':
        self._handlers.remove(handler)
        return self


class RecordUpdateListener:
    def update_record(  # pylint: disable=no-self-use
        self, zc: 'Zeroconf', now: float, record: DNSRecord
    ) -> None:
        """Update a single record.

        This method is deprecated and will be removed in a future version.
        update_records should be implemented instead.
        """
        raise RuntimeError("update_record is deprecated and will be removed in a future version.")

    def update_records(self, zc: 'Zeroconf', now: float, records: List[DNSRecord]) -> None:
        """Update multiple records in one shot.

        All records that are received in a single packet are passed
        to update_records.

        This implementation is a compatiblity shim to ensure older code
        that uses RecordUpdateListener as a base class will continue to
        get calls to update_record. This method will raise
        NotImplementedError in a future version.

        At this point the cache will not have the new records
        """
        for record in records:
            self.update_record(zc, now, record)

    def update_records_complete(self) -> None:
        """Called when a record update has completed for all handlers.

        At this point the cache will have the new records.
        """


class ServiceListener:
    def add_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()

    def remove_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()

    def update_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()


class NotifyListener:
    """Receive notifications Zeroconf.notify_all is called."""

    def notify_all(self) -> None:
        """Called when Zeroconf.notify_all is called."""
        raise NotImplementedError()


class _ServiceBrowserBase(RecordUpdateListener):
    """Base class for ServiceBrowser."""

    def __init__(
        self,
        zc: 'Zeroconf',
        type_: Union[str, list],
        handlers: Optional[Union[ServiceListener, List[Callable[..., None]]]] = None,
        listener: Optional[ServiceListener] = None,
        addr: Optional[str] = None,
        port: int = _MDNS_PORT,
        delay: int = _BROWSER_TIME,
    ) -> None:
        """Creates a browser for a specific type"""
        assert handlers or listener, 'You need to specify at least one handler'
        self.types = set(type_ if isinstance(type_, list) else [type_])  # type: Set[str]
        for check_type_ in self.types:
            if not check_type_.endswith(service_type_name(check_type_, strict=False)):
                raise BadTypeInNameException
        self.zc = zc
        self.addr = addr
        self.port = port
        self.multicast = self.addr in (None, _MDNS_ADDR, _MDNS_ADDR6)
        self._services = {
            check_type_: {} for check_type_ in self.types
        }  # type: Dict[str, Dict[str, DNSRecord]]
        current_time = current_time_millis()
        self._next_time = {check_type_: current_time for check_type_ in self.types}
        self._delay = {check_type_: delay for check_type_ in self.types}
        self._pending_handlers = OrderedDict()  # type: OrderedDict[Tuple[str, str], ServiceStateChange]
        self._handlers_to_call = OrderedDict()  # type: OrderedDict[Tuple[str, str], ServiceStateChange]

        self._service_state_changed = Signal()

        self.done = False

        if hasattr(handlers, 'add_service'):
            listener = cast(ServiceListener, handlers)
            handlers = None

        handlers = cast(List[Callable[..., None]], handlers or [])

        if listener:

            def on_change(
                zeroconf: 'Zeroconf', service_type: str, name: str, state_change: ServiceStateChange
            ) -> None:
                assert listener is not None
                args = (zeroconf, service_type, name)
                if state_change is ServiceStateChange.Added:
                    listener.add_service(*args)
                elif state_change is ServiceStateChange.Removed:
                    listener.remove_service(*args)
                elif state_change is ServiceStateChange.Updated:
                    if hasattr(listener, 'update_service'):
                        listener.update_service(*args)
                    else:
                        warnings.warn(
                            "%r has no update_service method. Provide one (it can be empty if you "
                            "don't care about the updates), it'll become mandatory." % (listener,),
                            FutureWarning,
                        )
                else:
                    raise NotImplementedError(state_change)

            handlers.append(on_change)

        for h in handlers:
            self.service_state_changed.register_handler(h)

    @property
    def service_state_changed(self) -> SignalRegistrationInterface:
        return self._service_state_changed.registration_interface

    def _record_matching_type(self, record: DNSRecord) -> Optional[str]:
        """Return the type if the record matches one of the types we are browsing."""
        return next((type_ for type_ in self.types if record.name.endswith(type_)), None)

    def _enqueue_callback(
        self,
        state_change: ServiceStateChange,
        type_: str,
        name: str,
    ) -> None:
        # Code to ensure we only do a single update message
        # Precedence is; Added, Remove, Update
        key = (name, type_)
        if (
            state_change is ServiceStateChange.Added
            or (
                state_change is ServiceStateChange.Removed
                and self._pending_handlers.get(key) != ServiceStateChange.Added
            )
            or (state_change is ServiceStateChange.Updated and key not in self._pending_handlers)
        ):
            self._pending_handlers[key] = state_change

    def _process_record_update(
        self,
        zc: 'Zeroconf',
        now: float,
        record: DNSRecord,
    ) -> None:
        """Process a single record update from a batch of updates."""
        expired = record.is_expired(now)

        if isinstance(record, DNSPointer):
            if record.name not in self.types:
                return
            service_key = record.alias.lower()
            services_by_type = self._services[record.name]
            old_record = services_by_type.get(service_key)
            if old_record is None:
                services_by_type[service_key] = record
                self._enqueue_callback(ServiceStateChange.Added, record.name, record.alias)
            elif expired:
                del services_by_type[service_key]
                self._enqueue_callback(ServiceStateChange.Removed, record.name, record.alias)
            else:
                old_record.reset_ttl(record)
                expires = record.get_expiration_time(_EXPIRE_REFRESH_TIME_PERCENT)
                if expires < self._next_time[record.name]:
                    self._next_time[record.name] = expires
            return

        # If its expired or already exists in the cache it cannot be updated.
        if expired or self.zc.cache.get(record):
            return

        if isinstance(record, DNSAddress):
            # Only trigger an updated event if the address is new
            if record.address in set(
                service.address
                for service in zc.cache.entries_with_name(record.name)
                if isinstance(service, DNSAddress)
            ):
                return

            # Iterate through the DNSCache and callback any services that use this address
            for service in self.zc.cache.entries_with_server(record.name):
                type_ = self._record_matching_type(service)
                if type_:
                    self._enqueue_callback(ServiceStateChange.Updated, type_, service.name)
                    break

            return

        type_ = self._record_matching_type(record)
        if type_:
            self._enqueue_callback(ServiceStateChange.Updated, type_, record.name)

    def update_records(self, zc: 'Zeroconf', now: float, records: List[DNSRecord]) -> None:
        """Callback invoked by Zeroconf when new information arrives.

        Updates information required by browser in the Zeroconf cache.

        Ensures that there is are no unecessary duplicates in the list.
        """
        for record in records:
            self._process_record_update(zc, now, record)

    def update_records_complete(self) -> None:
        """Called when a record update has completed for all handlers.

        At this point the cache will have the new records.
        """
        self._handlers_to_call.update(self._pending_handlers)
        self._pending_handlers.clear()

    def cancel(self) -> None:
        """Cancel the browser."""
        self.done = True
        self.zc.remove_listener(self)

    def run(self) -> None:
        """Run the browser."""
        questions = [DNSQuestion(type_, _TYPE_PTR, _CLASS_IN) for type_ in self.types]
        self.zc.add_listener(self, questions)

    def generate_ready_queries(self) -> Optional[DNSOutgoing]:
        """Generate the service browser query for any type that is due."""
        out = None
        now = current_time_millis()

        if min(self._next_time.values()) > now:
            return out

        for type_, due in self._next_time.items():
            if due > now:
                continue

            if out is None:
                out = DNSOutgoing(_FLAGS_QR_QUERY, multicast=self.multicast)
            out.add_question(DNSQuestion(type_, _TYPE_PTR, _CLASS_IN))

            for record in self._services[type_].values():
                if not record.is_stale(now):
                    out.add_answer_at_time(record, now)

            self._next_time[type_] = now + self._delay[type_]
            self._delay[type_] = min(_BROWSER_BACKOFF_LIMIT * 1000, self._delay[type_] * 2)
        return out

    def _seconds_to_wait(self) -> Optional[float]:
        """Returns the number of seconds to wait for the next event."""
        # If there are handlers to call
        # we want to process them right away
        if self._handlers_to_call:
            return None

        # Wait for the type has the smallest next time
        next_time = min(self._next_time.values())
        now = current_time_millis()

        if next_time <= now:
            return None

        return millis_to_seconds(next_time - now)


class ServiceBrowser(_ServiceBrowserBase, threading.Thread):
    """Used to browse for a service of a specific type.

    The listener object will have its add_service() and
    remove_service() methods called when this browser
    discovers changes in the services availability."""

    def __init__(
        self,
        zc: 'Zeroconf',
        type_: Union[str, list],
        handlers: Optional[Union[ServiceListener, List[Callable[..., None]]]] = None,
        listener: Optional[ServiceListener] = None,
        addr: Optional[str] = None,
        port: int = _MDNS_PORT,
        delay: int = _BROWSER_TIME,
    ) -> None:
        threading.Thread.__init__(self)
        super().__init__(zc, type_, handlers=handlers, listener=listener, addr=addr, port=port, delay=delay)
        self.daemon = True
        self.start()
        self.name = "zeroconf-ServiceBrowser-%s-%s" % (
            '-'.join([type_[:-7] for type_ in self.types]),
            getattr(self, 'native_id', self.ident),
        )

    def cancel(self) -> None:
        """Cancel the browser."""
        super().cancel()
        self.join()

    def run(self) -> None:
        """Run the browser thread."""
        super().run()
        while True:
            timeout = self._seconds_to_wait()
            if timeout:
                with self.zc.condition:
                    # We must check again while holding the condition
                    # in case the other thread has added to _handlers_to_call
                    # between when we checked above when we were not
                    # holding the condition
                    if not self._handlers_to_call:
                        self.zc.condition.wait(timeout)

            if self.zc.done or self.done:
                return

            out = self.generate_ready_queries()
            if out:
                self.zc.send(out, addr=self.addr, port=self.port)

            if not self._handlers_to_call:
                continue

            (name_type, state_change) = self._handlers_to_call.popitem(False)
            self._service_state_changed.fire(
                zeroconf=self.zc,
                service_type=name_type[1],
                name=name_type[0],
                state_change=state_change,
            )


class ServiceInfo(RecordUpdateListener):
    """Service information.

    Constructor parameters are as follows:

    * `type_`: fully qualified service type name
    * `name`: fully qualified service name
    * `port`: port that the service runs on
    * `weight`: weight of the service
    * `priority`: priority of the service
    * `properties`: dictionary of properties (or a bytes object holding the contents of the `text` field).
      converted to str and then encoded to bytes using UTF-8. Keys with `None` values are converted to
      value-less attributes.
    * `server`: fully qualified name for service host (defaults to name)
    * `host_ttl`: ttl used for A/SRV records
    * `other_ttl`: ttl used for PTR/TXT records
    * `addresses` and `parsed_addresses`: List of IP addresses (either as bytes, network byte order,
      or in parsed form as text; at most one of those parameters can be provided)

    """

    text = b''

    def __init__(
        self,
        type_: str,
        name: str,
        port: Optional[int] = None,
        weight: int = 0,
        priority: int = 0,
        properties: Union[bytes, Dict] = b'',
        server: Optional[str] = None,
        host_ttl: int = _DNS_HOST_TTL,
        other_ttl: int = _DNS_OTHER_TTL,
        *,
        addresses: Optional[List[bytes]] = None,
        parsed_addresses: Optional[List[str]] = None
    ) -> None:
        # Accept both none, or one, but not both.
        if addresses is not None and parsed_addresses is not None:
            raise TypeError("addresses and parsed_addresses cannot be provided together")
        if not type_.endswith(service_type_name(name, strict=False)):
            raise BadTypeInNameException
        self.type = type_
        self.name = name
        self.key = name.lower()
        if addresses is not None:
            self._addresses = addresses
        elif parsed_addresses is not None:
            self._addresses = [_encode_address(a) for a in parsed_addresses]
        else:
            self._addresses = []
        # This results in an ugly error when registering, better check now
        invalid = [a for a in self._addresses if not isinstance(a, bytes) or len(a) not in (4, 16)]
        if invalid:
            raise TypeError(
                'Addresses must be bytes, got %s. Hint: convert string addresses '
                'with socket.inet_pton' % invalid
            )
        self.port = port
        self.weight = weight
        self.priority = priority
        if server:
            self.server = server
        else:
            self.server = name
        self.server_key = self.server.lower()
        self._properties = {}  # type: Dict
        self._set_properties(properties)
        self.host_ttl = host_ttl
        self.other_ttl = other_ttl

    @property
    def addresses(self) -> List[bytes]:
        """IPv4 addresses of this service.

        Only IPv4 addresses are returned for backward compatibility.
        Use :meth:`addresses_by_version` or :meth:`parsed_addresses` to
        include IPv6 addresses as well.
        """
        return self.addresses_by_version(IPVersion.V4Only)

    @addresses.setter
    def addresses(self, value: List[bytes]) -> None:
        """Replace the addresses list.

        This replaces all currently stored addresses, both IPv4 and IPv6.
        """
        self._addresses = value

    @property
    def properties(self) -> Dict:
        """If properties were set in the constructor this property returns the original dictionary
        of type `Dict[Union[bytes, str], Any]`.

        If properties are coming from the network, after decoding a TXT record, the keys are always
        bytes and the values are either bytes, if there was a value, even empty, or `None`, if there
        was none. No further decoding is attempted. The type returned is `Dict[bytes, Optional[bytes]]`.
        """
        return self._properties

    def addresses_by_version(self, version: IPVersion) -> List[bytes]:
        """List addresses matching IP version."""
        if version == IPVersion.V4Only:
            return [addr for addr in self._addresses if not _is_v6_address(addr)]
        if version == IPVersion.V6Only:
            return list(filter(_is_v6_address, self._addresses))
        return self._addresses

    def parsed_addresses(self, version: IPVersion = IPVersion.All) -> List[str]:
        """List addresses in their parsed string form."""
        result = self.addresses_by_version(version)
        return [
            socket.inet_ntop(socket.AF_INET6 if _is_v6_address(addr) else socket.AF_INET, addr)
            for addr in result
        ]

    def _set_properties(self, properties: Union[bytes, Dict]) -> None:
        """Sets properties and text of this info from a dictionary"""
        if isinstance(properties, dict):
            self._properties = properties
            list_ = []
            result = b''
            for key, value in properties.items():
                if isinstance(key, str):
                    key = key.encode('utf-8')

                record = key
                if value is not None:
                    if not isinstance(value, bytes):
                        value = str(value).encode('utf-8')
                    record += b'=' + value
                list_.append(record)
            for item in list_:
                result = b''.join((result, int2byte(len(item)), item))
            self.text = result
        else:
            self.text = properties

    def _set_text(self, text: bytes) -> None:
        """Sets properties and text given a text field"""
        self.text = text
        result = {}  # type: Dict
        end = len(text)
        index = 0
        strs = []
        while index < end:
            length = text[index]
            index += 1
            strs.append(text[index : index + length])
            index += length

        for s in strs:
            parts = s.split(b'=', 1)
            try:
                key, value = parts  # type: Tuple[bytes, Optional[bytes]]
            except ValueError:
                # No equals sign at all
                key = s
                value = None

            # Only update non-existent properties
            if key and result.get(key) is None:
                result[key] = value

        self._properties = result

    def get_name(self) -> str:
        """Name accessor"""
        return self.name[: len(self.name) - len(self.type) - 1]

    def update_record(self, zc: 'Zeroconf', now: float, record: Optional[DNSRecord]) -> None:
        """Updates service information from a DNS record.

        This method is deprecated and will be removed in a future version.
        update_records should be implemented instead.
        """
        if record is not None:
            self.update_records(zc, now, [record])

    def update_records(self, zc: 'Zeroconf', now: float, records: List[DNSRecord]) -> None:
        """Updates service information from a DNS record."""
        update_addresses = False
        for record in records:
            if isinstance(record, DNSService):
                update_addresses = True
            self._process_record(record, now)

        # Only update addresses if the DNSService (.server) has changed
        if not update_addresses:
            return

        for record in self._get_address_records_from_cache(zc):
            self._process_record(record, now)

    def _process_record(self, record: DNSRecord, now: float) -> None:
        if record.is_expired(now):
            return

        if isinstance(record, DNSAddress):
            if record.key == self.server_key and record.address not in self._addresses:
                self._addresses.append(record.address)
            return

        if isinstance(record, DNSService):
            if record.key != self.key:
                return
            self.name = record.name
            self.server = record.server
            self.server_key = record.server.lower()
            self.port = record.port
            self.weight = record.weight
            self.priority = record.priority
            return

        if isinstance(record, DNSText):
            if record.key == self.key:
                self._set_text(record.text)

    def dns_addresses(self, override_ttl: Optional[int] = None) -> List[DNSAddress]:
        """Return matching DNSAddress from ServiceInfo."""
        return [
            DNSAddress(
                self.server,
                _TYPE_AAAA if _is_v6_address(address) else _TYPE_A,
                _CLASS_IN | _CLASS_UNIQUE,
                override_ttl if override_ttl is not None else self.host_ttl,
                address,
            )
            for address in self._addresses
        ]

    def dns_pointer(self, override_ttl: Optional[int] = None) -> DNSPointer:
        """Return DNSPointer from ServiceInfo."""
        return DNSPointer(
            self.type,
            _TYPE_PTR,
            _CLASS_IN,
            override_ttl if override_ttl is not None else self.other_ttl,
            self.name,
        )

    def dns_service(self, override_ttl: Optional[int] = None) -> DNSService:
        """Return DNSService from ServiceInfo."""
        return DNSService(
            self.name,
            _TYPE_SRV,
            _CLASS_IN | _CLASS_UNIQUE,
            override_ttl if override_ttl is not None else self.host_ttl,
            self.priority,
            self.weight,
            cast(int, self.port),
            self.server,
        )

    def dns_text(self, override_ttl: Optional[int] = None) -> DNSText:
        """Return DNSText from ServiceInfo."""
        return DNSText(
            self.name,
            _TYPE_TXT,
            _CLASS_IN | _CLASS_UNIQUE,
            override_ttl if override_ttl is not None else self.other_ttl,
            self.text,
        )

    def _get_address_records_from_cache(self, zc: 'Zeroconf') -> List[DNSRecord]:
        """Get the address records from the cache."""
        address_records = []
        cached_a_record = zc.cache.get_by_details(self.server, _TYPE_A, _CLASS_IN)
        if cached_a_record:
            address_records.append(cached_a_record)
        address_records.extend(zc.cache.get_all_by_details(self.server, _TYPE_AAAA, _CLASS_IN))
        return address_records

    def load_from_cache(self, zc: 'Zeroconf') -> bool:
        """Populate the service info from the cache."""
        now = current_time_millis()
        record_updates = []
        cached_srv_record = zc.cache.get_by_details(self.name, _TYPE_SRV, _CLASS_IN)
        if cached_srv_record:
            # If there is a srv record, A and AAAA will already
            # be called and we do not want to do it twice
            record_updates.append(cached_srv_record)
        else:
            record_updates.extend(self._get_address_records_from_cache(zc))
        cached_txt_record = zc.cache.get_by_details(self.name, _TYPE_TXT, _CLASS_IN)
        if cached_txt_record:
            record_updates.append(cached_txt_record)
        self.update_records(zc, now, record_updates)
        return self._is_complete

    @property
    def _is_complete(self) -> bool:
        """The ServiceInfo has all expected properties."""
        return not (self.text is None or not self._addresses)

    def request(self, zc: 'Zeroconf', timeout: float) -> bool:
        """Returns true if the service could be discovered on the
        network, and updates this object with details discovered.
        """
        if self.load_from_cache(zc):
            return True

        now = current_time_millis()
        delay = _LISTENER_TIME
        next_ = now
        last = now + timeout
        try:
            # Do not set a question on the listener to preload from cache
            # since we just checked it above in load_from_cache
            zc.add_listener(self, None)
            while not self._is_complete:
                if last <= now:
                    return False
                if next_ <= now:
                    out = self.generate_request_query(zc, now)
                    if not out.questions:
                        return True
                    zc.send(out)
                    next_ = now + delay
                    delay *= 2

                zc.wait(min(next_, last) - now)
                now = current_time_millis()
        finally:
            zc.remove_listener(self)

        return True

    def generate_request_query(self, zc: 'Zeroconf', now: float) -> DNSOutgoing:
        """Generate the request query."""
        out = DNSOutgoing(_FLAGS_QR_QUERY)
        out.add_question_or_one_cache(zc.cache, now, self.name, _TYPE_SRV, _CLASS_IN)
        out.add_question_or_one_cache(zc.cache, now, self.name, _TYPE_TXT, _CLASS_IN)
        out.add_question_or_one_cache(zc.cache, now, self.server, _TYPE_A, _CLASS_IN)
        out.add_question_or_all_cache(zc.cache, now, self.server, _TYPE_AAAA, _CLASS_IN)
        return out

    def __eq__(self, other: object) -> bool:
        """Tests equality of service name"""
        return isinstance(other, ServiceInfo) and other.name == self.name

    def __repr__(self) -> str:
        """String representation"""
        return '%s(%s)' % (
            type(self).__name__,
            ', '.join(
                '%s=%r' % (name, getattr(self, name))
                for name in (
                    'type',
                    'name',
                    'addresses',
                    'port',
                    'weight',
                    'priority',
                    'server',
                    'properties',
                )
            ),
        )


class ZeroconfServiceTypes(ServiceListener):
    """
    Return all of the advertised services on any local networks
    """

    def __init__(self) -> None:
        """Keep track of found services in a set."""
        self.found_services = set()  # type: Set[str]

    def add_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        """Service added."""
        self.found_services.add(name)

    def update_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        """Service updated."""

    def remove_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        """Service removed."""

    @classmethod
    def find(
        cls,
        zc: Optional['Zeroconf'] = None,
        timeout: Union[int, float] = 5,
        interfaces: InterfacesType = InterfaceChoice.All,
        ip_version: Optional[IPVersion] = None,
    ) -> Tuple[str, ...]:
        """
        Return all of the advertised services on any local networks.

        :param zc: Zeroconf() instance.  Pass in if already have an
                instance running or if non-default interfaces are needed
        :param timeout: seconds to wait for any responses
        :param interfaces: interfaces to listen on.
        :param ip_version: IP protocol version to use.
        :return: tuple of service type strings
        """
        local_zc = zc or Zeroconf(interfaces=interfaces, ip_version=ip_version)
        listener = cls()
        browser = ServiceBrowser(local_zc, _SERVICE_TYPE_ENUMERATION_NAME, listener=listener)

        # wait for responses
        time.sleep(timeout)

        browser.cancel()

        # close down anything we opened
        if zc is None:
            local_zc.close()

        return tuple(sorted(listener.found_services))


def get_all_addresses() -> List[str]:
    return list(set(addr.ip for iface in ifaddr.get_adapters() for addr in iface.ips if addr.is_IPv4))


def get_all_addresses_v6() -> List[Tuple[Tuple[str, int, int], int]]:
    # IPv6 multicast uses positive indexes for interfaces
    # TODO: What about multi-address interfaces?
    return list(
        set((addr.ip, iface.index) for iface in ifaddr.get_adapters() for addr in iface.ips if addr.is_IPv6)
    )


def ip6_to_address_and_index(adapters: List[Any], ip: str) -> Tuple[Tuple[str, int, int], int]:
    ipaddr = ipaddress.ip_address(ip)
    for adapter in adapters:
        for adapter_ip in adapter.ips:
            # IPv6 addresses are represented as tuples
            if isinstance(adapter_ip.ip, tuple) and ipaddress.ip_address(adapter_ip.ip[0]) == ipaddr:
                return (cast(Tuple[str, int, int], adapter_ip.ip), cast(int, adapter.index))

    raise RuntimeError('No adapter found for IP address %s' % ip)


def interface_index_to_ip6_address(adapters: List[Any], index: int) -> Tuple[str, int, int]:
    for adapter in adapters:
        if adapter.index == index:
            for adapter_ip in adapter.ips:
                # IPv6 addresses are represented as tuples
                if isinstance(adapter_ip.ip, tuple):
                    return cast(Tuple[str, int, int], adapter_ip.ip)

    raise RuntimeError('No adapter found for index %s' % index)


def ip6_addresses_to_indexes(
    interfaces: List[Union[str, int, Tuple[Tuple[str, int, int], int]]]
) -> List[Tuple[Tuple[str, int, int], int]]:
    """Convert IPv6 interface addresses to interface indexes.

    IPv4 addresses are ignored.

    :param interfaces: List of IP addresses and indexes.
    :returns: List of indexes.
    """
    result = []
    adapters = ifaddr.get_adapters()

    for iface in interfaces:
        if isinstance(iface, int):
            result.append((interface_index_to_ip6_address(adapters, iface), iface))
        elif isinstance(iface, str) and ipaddress.ip_address(iface).version == 6:
            result.append(ip6_to_address_and_index(adapters, iface))

    return result


def normalize_interface_choice(
    choice: InterfacesType, ip_version: IPVersion = IPVersion.V4Only
) -> List[Union[str, Tuple[Tuple[str, int, int], int]]]:
    """Convert the interfaces choice into internal representation.

    :param choice: `InterfaceChoice` or list of interface addresses or indexes (IPv6 only).
    :param ip_address: IP version to use (ignored if `choice` is a list).
    :returns: List of IP addresses (for IPv4) and indexes (for IPv6).
    """
    result = []  # type: List[Union[str, Tuple[Tuple[str, int, int], int]]]
    if choice is InterfaceChoice.Default:
        if ip_version != IPVersion.V4Only:
            # IPv6 multicast uses interface 0 to mean the default
            result.append((('', 0, 0), 0))
        if ip_version != IPVersion.V6Only:
            result.append('0.0.0.0')
    elif choice is InterfaceChoice.All:
        if ip_version != IPVersion.V4Only:
            result.extend(get_all_addresses_v6())
        if ip_version != IPVersion.V6Only:
            result.extend(get_all_addresses())
        if not result:
            raise RuntimeError(
                'No interfaces to listen on, check that any interfaces have IP version %s' % ip_version
            )
    elif isinstance(choice, list):
        # First, take IPv4 addresses.
        result = [i for i in choice if isinstance(i, str) and ipaddress.ip_address(i).version == 4]
        # Unlike IP_ADD_MEMBERSHIP, IPV6_JOIN_GROUP requires interface indexes.
        result += ip6_addresses_to_indexes(choice)
    else:
        raise TypeError("choice must be a list or InterfaceChoice, got %r" % choice)
    return result


def new_socket(  # pylint: disable=too-many-branches
    bind_addr: Union[Tuple[str], Tuple[str, int, int]],
    port: int = _MDNS_PORT,
    ip_version: IPVersion = IPVersion.V4Only,
    apple_p2p: bool = False,
) -> socket.socket:
    log.debug(
        'Creating new socket with port %s, ip_version %s, apple_p2p %s and bind_addr %r',
        port,
        ip_version,
        apple_p2p,
        bind_addr,
    )
    if ip_version == IPVersion.V4Only:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    else:
        s = socket.socket(socket.AF_INET6, socket.SOCK_DGRAM)

    if ip_version == IPVersion.All:
        # make V6 sockets work for both V4 and V6 (required for Windows)
        try:
            s.setsockopt(_IPPROTO_IPV6, socket.IPV6_V6ONLY, False)
        except OSError:
            log.error('Support for dual V4-V6 sockets is not present, use IPVersion.V4 or IPVersion.V6')
            raise

    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)

    # SO_REUSEADDR should be equivalent to SO_REUSEPORT for
    # multicast UDP sockets (p 731, "TCP/IP Illustrated,
    # Volume 2"), but some BSD-derived systems require
    # SO_REUSEPORT to be specified explicitly.  Also, not all
    # versions of Python have SO_REUSEPORT available.
    # Catch OSError and socket.error for kernel versions <3.9 because lacking
    # SO_REUSEPORT support.
    try:
        reuseport = socket.SO_REUSEPORT
    except AttributeError:
        pass
    else:
        try:
            s.setsockopt(socket.SOL_SOCKET, reuseport, 1)
        except OSError as err:
            if err.errno != errno.ENOPROTOOPT:
                raise

    if port == _MDNS_PORT:
        ttl = struct.pack(b'B', 255)
        loop = struct.pack(b'B', 1)
        if ip_version != IPVersion.V6Only:
            # OpenBSD needs the ttl and loop values for the IP_MULTICAST_TTL and
            # IP_MULTICAST_LOOP socket options as an unsigned char.
            try:
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
                s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop)
            except socket.error as e:
                if bind_addr[0] != '' or get_errno(e) != errno.EINVAL:  # Fails to set on MacOS
                    raise
        if ip_version != IPVersion.V4Only:
            # However, char doesn't work here (at least on Linux)
            s.setsockopt(_IPPROTO_IPV6, socket.IPV6_MULTICAST_HOPS, 255)
            s.setsockopt(_IPPROTO_IPV6, socket.IPV6_MULTICAST_LOOP, True)

    if apple_p2p:
        # SO_RECV_ANYIF = 0x1104
        # https://opensource.apple.com/source/xnu/xnu-4570.41.2/bsd/sys/socket.h
        s.setsockopt(socket.SOL_SOCKET, 0x1104, 1)

    s.bind((bind_addr[0], port, *bind_addr[1:]))
    log.debug('Created socket %s', s)
    return s


def add_multicast_member(
    listen_socket: socket.socket,
    interface: Union[str, Tuple[Tuple[str, int, int], int]],
) -> bool:
    # This is based on assumptions in normalize_interface_choice
    is_v6 = isinstance(interface, tuple)
    err_einval = {errno.EINVAL}
    if sys.platform == 'win32':
        # No WSAEINVAL definition in typeshed
        err_einval |= {cast(Any, errno).WSAEINVAL}  # pylint: disable=no-member
    log.debug('Adding %r (socket %d) to multicast group', interface, listen_socket.fileno())
    try:
        if is_v6:
            iface_bin = struct.pack('@I', cast(int, interface[1]))
            _value = _MDNS_ADDR6_BYTES + iface_bin
            listen_socket.setsockopt(_IPPROTO_IPV6, socket.IPV6_JOIN_GROUP, _value)
        else:
            _value = _MDNS_ADDR_BYTES + socket.inet_aton(cast(str, interface))
            listen_socket.setsockopt(socket.IPPROTO_IP, socket.IP_ADD_MEMBERSHIP, _value)
    except socket.error as e:
        _errno = get_errno(e)
        if _errno == errno.EADDRINUSE:
            log.info(
                'Address in use when adding %s to multicast group, '
                'it is expected to happen on some systems',
                interface,
            )
            return False
        if _errno == errno.EADDRNOTAVAIL:
            log.info(
                'Address not available when adding %s to multicast '
                'group, it is expected to happen on some systems',
                interface,
            )
            return False
        if _errno in err_einval:
            log.info('Interface of %s does not support multicast, ' 'it is expected in WSL', interface)
            return False
        raise
    return True


def new_respond_socket(
    interface: Union[str, Tuple[Tuple[str, int, int], int]],
    apple_p2p: bool = False,
) -> Optional[socket.socket]:
    is_v6 = isinstance(interface, tuple)
    respond_socket = new_socket(
        ip_version=(IPVersion.V6Only if is_v6 else IPVersion.V4Only),
        apple_p2p=apple_p2p,
        bind_addr=cast(Tuple[Tuple[str, int, int], int], interface)[0] if is_v6 else (cast(str, interface),),
    )
    log.debug('Configuring socket %s with multicast interface %s', respond_socket, interface)
    if is_v6:
        iface_bin = struct.pack('@I', cast(int, interface[1]))
        respond_socket.setsockopt(_IPPROTO_IPV6, socket.IPV6_MULTICAST_IF, iface_bin)
    else:
        respond_socket.setsockopt(
            socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(cast(str, interface))
        )
    return respond_socket


def create_sockets(
    interfaces: InterfacesType = InterfaceChoice.All,
    unicast: bool = False,
    ip_version: IPVersion = IPVersion.V4Only,
    apple_p2p: bool = False,
) -> Tuple[Optional[socket.socket], List[socket.socket]]:
    if unicast:
        listen_socket = None
    else:
        listen_socket = new_socket(ip_version=ip_version, apple_p2p=apple_p2p, bind_addr=('',))

    normalized_interfaces = normalize_interface_choice(interfaces, ip_version)

    # If we are using InterfaceChoice.Default we can use
    # a single socket to listen and respond.
    if not unicast and interfaces is InterfaceChoice.Default:
        for i in normalized_interfaces:
            add_multicast_member(cast(socket.socket, listen_socket), i)
        return listen_socket, [cast(socket.socket, listen_socket)]

    respond_sockets = []

    for i in normalized_interfaces:
        if not unicast:
            if add_multicast_member(cast(socket.socket, listen_socket), i):
                respond_socket = new_respond_socket(i, apple_p2p=apple_p2p)
            else:
                respond_socket = None
        else:
            respond_socket = new_socket(
                port=0,
                ip_version=ip_version,
                apple_p2p=apple_p2p,
                bind_addr=i[0] if isinstance(i, tuple) else (i,),
            )

        if respond_socket is not None:
            respond_sockets.append(respond_socket)

    return listen_socket, respond_sockets


def get_errno(e: Exception) -> int:
    assert isinstance(e, socket.error)
    return cast(int, e.args[0])


def can_send_to(sock: socket.socket, address: str) -> bool:
    addr = ipaddress.ip_address(address)
    return cast(bool, addr.version == 6 if sock.family == socket.AF_INET6 else addr.version == 4)


def autodetect_ip_version(interfaces: InterfacesType) -> IPVersion:
    """Auto detect the IP version when it is not provided."""
    if isinstance(interfaces, list):
        has_v6 = any(
            isinstance(i, int) or (isinstance(i, str) and ipaddress.ip_address(i).version == 6)
            for i in interfaces
        )
        has_v4 = any(isinstance(i, str) and ipaddress.ip_address(i).version == 4 for i in interfaces)
        if has_v4 and has_v6:
            return IPVersion.All
        if has_v6:
            return IPVersion.V6Only

    return IPVersion.V4Only


class ServiceRegistry:
    """A registry to keep track of services.

    This class exists to ensure services can
    be safely added and removed with thread
    safety.
    """

    def __init__(
        self,
    ) -> None:
        """Create the ServiceRegistry class."""
        self.services = {}  # type: Dict[str, ServiceInfo]
        self.types = {}  # type: Dict[str, List]
        self.servers = {}  # type: Dict[str, List]
        self._lock = threading.Lock()  # add and remove services thread safe

    def add(self, info: ServiceInfo) -> None:
        """Add a new service to the registry."""

        with self._lock:
            self._add(info)

    def remove(self, info: ServiceInfo) -> None:
        """Remove a new service from the registry."""

        with self._lock:
            self._remove(info)

    def update(self, info: ServiceInfo) -> None:
        """Update new service in the registry."""

        with self._lock:
            self._remove(info)
            self._add(info)

    def get_service_infos(self) -> List[ServiceInfo]:
        """Return all ServiceInfo."""
        return list(self.services.values())

    def get_info_name(self, name: str) -> Optional[ServiceInfo]:
        """Return all ServiceInfo for the name."""
        return self.services.get(name)

    def get_types(self) -> List[str]:
        """Return all types."""
        return list(self.types.keys())

    def get_infos_type(self, type_: str) -> List[ServiceInfo]:
        """Return all ServiceInfo matching type."""
        return self._get_by_index("types", type_)

    def get_infos_server(self, server: str) -> List[ServiceInfo]:
        """Return all ServiceInfo matching server."""
        return self._get_by_index("servers", server)

    def _get_by_index(self, attr: str, key: str) -> List[ServiceInfo]:
        """Return all ServiceInfo matching the index."""
        service_infos = []

        for name in getattr(self, attr).get(key, [])[:]:
            info = self.services.get(name)
            # Since we do not get under a lock since it would be
            # a performance issue, its possible
            # the service can be unregistered during the get
            # so we must check if info is None
            if info is not None:
                service_infos.append(info)

        return service_infos

    def _add(self, info: ServiceInfo) -> None:
        """Add a new service under the lock."""
        lower_name = info.name.lower()
        if lower_name in self.services:
            raise ServiceNameAlreadyRegistered

        self.services[lower_name] = info
        self.types.setdefault(info.type, []).append(lower_name)
        self.servers.setdefault(info.server, []).append(lower_name)

    def _remove(self, info: ServiceInfo) -> None:
        """Remove a service under the lock."""
        lower_name = info.name.lower()
        old_service_info = self.services[lower_name]
        self.types[old_service_info.type].remove(lower_name)
        self.servers[old_service_info.server].remove(lower_name)
        del self.services[lower_name]


class QueryHandler:
    """Query the ServiceRegistry."""

    def __init__(self, registry: ServiceRegistry):
        """Init the query handler."""
        self.registry = registry

    def _answer_service_type_enumeration_query(self, msg: DNSIncoming, out: DNSOutgoing) -> None:
        """Provide an answer to a service type enumeration query.

        https://datatracker.ietf.org/doc/html/rfc6763#section-9
        """
        for stype in self.registry.get_types():
            out.add_answer(
                msg,
                DNSPointer(
                    _SERVICE_TYPE_ENUMERATION_NAME,
                    _TYPE_PTR,
                    _CLASS_IN,
                    _DNS_OTHER_TTL,
                    stype,
                ),
            )

    def _answer_ptr_query(self, msg: DNSIncoming, out: DNSOutgoing, question: DNSQuestion) -> None:
        """Answer a PTR query."""
        for service in self.registry.get_infos_type(question.name.lower()):
            out.add_answer(msg, service.dns_pointer())
            # Add recommended additional answers according to
            # https://tools.ietf.org/html/rfc6763#section-12.1.
            out.add_additional_answer(service.dns_service())
            out.add_additional_answer(service.dns_text())
            for dns_address in service.dns_addresses():
                out.add_additional_answer(dns_address)

    def _answer_non_ptr_query(self, msg: DNSIncoming, out: DNSOutgoing, question: DNSQuestion) -> None:
        """Answer a query any query other then PTR.

        Add answer(s) for A, AAAA, SRV, or TXT queries.
        """
        name_to_find = question.name.lower()
        # Answer A record queries for any service addresses we know
        if question.type in (_TYPE_A, _TYPE_ANY):
            for service in self.registry.get_infos_server(name_to_find):
                for dns_address in service.dns_addresses():
                    out.add_answer(msg, dns_address)

        service = self.registry.get_info_name(name_to_find)  # type: ignore
        if service is None:
            return

        if question.type in (_TYPE_SRV, _TYPE_ANY):
            out.add_answer(msg, service.dns_service())
        if question.type in (_TYPE_TXT, _TYPE_ANY):
            out.add_answer(msg, service.dns_text())
        if question.type == _TYPE_SRV:
            for dns_address in service.dns_addresses():
                out.add_additional_answer(dns_address)

    def response(self, msg: DNSIncoming, unicast: bool) -> Optional[DNSOutgoing]:
        """Deal with incoming query packets. Provides a response if possible."""
        if unicast:
            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA, multicast=False)
            for question in msg.questions:
                out.add_question(question)
        else:
            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)

        for question in msg.questions:
            if question.type == _TYPE_PTR:
                if question.name.lower() == _SERVICE_TYPE_ENUMERATION_NAME:
                    self._answer_service_type_enumeration_query(msg, out)
                else:
                    self._answer_ptr_query(msg, out, question)
                continue

            self._answer_non_ptr_query(msg, out, question)

        if out is not None and out.answers:
            out.id = msg.id
            return out

        return None


class RecordManager:
    """Process records into the cache and notify listeners."""

    def __init__(self, zeroconf: 'Zeroconf') -> None:
        """Init the record manager."""
        self.zc = zeroconf
        self.cache = zeroconf.cache
        self.listeners: List[RecordUpdateListener] = []

    def updates(self, now: float, rec: List[DNSRecord]) -> None:
        """Used to notify listeners of new information that has updated
        a record.

        This method must be called before the cache is updated.
        """
        for listener in self.listeners:
            listener.update_records(self.zc, now, rec)

    def updates_complete(self) -> None:
        """Used to notify listeners of new information that has updated
        a record.

        This method must be called after the cache is updated.
        """
        for listener in self.listeners:
            listener.update_records_complete()
        self.zc.notify_all()

    def updates_from_response(self, msg: DNSIncoming) -> None:
        """Deal with incoming response packets.  All answers
        are held in the cache, and listeners are notified."""
        updates: List[DNSRecord] = []
        address_adds: List[DNSAddress] = []
        other_adds: List[DNSRecord] = []
        removes: List[DNSRecord] = []
        now = current_time_millis()
        for record in msg.answers:

            updated = True

            if record.unique:  # https://tools.ietf.org/html/rfc6762#section-10.2
                # rfc6762#section-10.2 para 2
                # Since unique is set, all old records with that name, rrtype,
                # and rrclass that were received more than one second ago are declared
                # invalid, and marked to expire from the cache in one second.
                for entry in self.cache.get_all_by_details(record.name, record.type, record.class_):
                    if entry == record:
                        updated = False
                    if record.created - entry.created > 1000 and entry not in msg.answers:
                        removes.append(entry)

            expired = record.is_expired(now)
            maybe_entry = self.cache.get(record)
            if not expired:
                if maybe_entry is not None:
                    maybe_entry.reset_ttl(record)
                else:
                    if isinstance(record, DNSAddress):
                        address_adds.append(record)
                    else:
                        other_adds.append(record)
                if updated:
                    updates.append(record)
            elif maybe_entry is not None:
                updates.append(record)
                removes.append(record)

        if not updates and not address_adds and not other_adds and not removes:
            return

        self.updates(now, updates)
        # The cache adds must be processed AFTER we trigger
        # the updates since we compare existing data
        # with the new data and updating the cache
        # ahead of update_record will cause listeners
        # to miss changes
        #
        # We must process address adds before non-addresses
        # otherwise a fetch of ServiceInfo may miss an address
        # because it thinks the cache is complete
        #
        # The cache is processed under the context manager to ensure
        # that any ServiceBrowser that is going to call
        # zc.get_service_info will see the cached value
        # but ONLY after all the record updates have been
        # processsed.
        self.cache.add_records(itertools.chain(address_adds, other_adds))
        # Removes are processed last since
        # ServiceInfo could generate an un-needed query
        # because the data was not yet populated.
        self.cache.remove_records(removes)
        self.updates_complete()

    def add_listener(
        self, listener: RecordUpdateListener, question: Optional[Union[DNSQuestion, List[DNSQuestion]]]
    ) -> None:
        """Adds a listener for a given question.  The listener will have
        its update_record method called when information is available to
        answer the question(s)."""
        self.listeners.append(listener)

        if question is not None:
            now = current_time_millis()
            records = []
            questions = [question] if isinstance(question, DNSQuestion) else question
            for single_question in questions:
                for record in self.cache.entries_with_name(single_question.name):
                    if single_question.answered_by(record) and not record.is_expired(now):
                        records.append(record)
            if records:
                listener.update_records(self.zc, now, records)
                listener.update_records_complete()

        self.zc.notify_all()

    def remove_listener(self, listener: RecordUpdateListener) -> None:
        """Removes a listener."""
        try:
            self.listeners.remove(listener)
            self.zc.notify_all()
        except ValueError as e:
            log.exception('Failed to remove listener: %r', e)


class Zeroconf(QuietLogger):

    """Implementation of Zeroconf Multicast DNS Service Discovery

    Supports registration, unregistration, queries and browsing.
    """

    def __init__(
        self,
        interfaces: InterfacesType = InterfaceChoice.All,
        unicast: bool = False,
        ip_version: Optional[IPVersion] = None,
        apple_p2p: bool = False,
    ) -> None:
        """Creates an instance of the Zeroconf class, establishing
        multicast communications, listening and reaping threads.

        :param interfaces: :class:`InterfaceChoice` or a list of IP addresses
            (IPv4 and IPv6) and interface indexes (IPv6 only).

            IPv6 notes for non-POSIX systems:
            * `InterfaceChoice.All` is an alias for `InterfaceChoice.Default`
              on Python versions before 3.8.

            Also listening on loopback (``::1``) doesn't work, use a real address.
        :param ip_version: IP versions to support. If `choice` is a list, the default is detected
            from it. Otherwise defaults to V4 only for backward compatibility.
        :param apple_p2p: use AWDL interface (only macOS)
        """
        if ip_version is None:
            ip_version = autodetect_ip_version(interfaces)

        # hook for threads
        self._GLOBAL_DONE = False
        self.unicast = unicast

        if apple_p2p and not platform.system() == 'Darwin':
            raise RuntimeError('Option `apple_p2p` is not supported on non-Apple platforms.')

        self._listen_socket, self._respond_sockets = create_sockets(
            interfaces, unicast, ip_version, apple_p2p=apple_p2p
        )
        log.debug('Listen socket %s, respond sockets %s', self._listen_socket, self._respond_sockets)
        self.multi_socket = unicast or interfaces is not InterfaceChoice.Default

        self._notify_listeners = []  # type: List[NotifyListener]
        self.browsers = {}  # type: Dict[ServiceListener, ServiceBrowser]
        self.registry = ServiceRegistry()
        self.query_handler = QueryHandler(self.registry)
        self.cache = DNSCache()
        self.record_manager = RecordManager(self)

        self.condition = threading.Condition()

        self.engine = Engine(self)
        self.listener = Listener(self)
        if not unicast:
            self.engine.add_reader(self.listener, cast(socket.socket, self._listen_socket))
        if self.multi_socket:
            for s in self._respond_sockets:
                self.engine.add_reader(self.listener, s)
        # Start the engine only after all
        # the readers have been added to avoid
        # missing any packets that are on the wire
        self.engine.start()

    @property
    def done(self) -> bool:
        return self._GLOBAL_DONE

    @property
    def listeners(self) -> List[RecordUpdateListener]:
        return self.record_manager.listeners

    def wait(self, timeout: float) -> None:
        """Calling thread waits for a given number of milliseconds or
        until notified."""
        with self.condition:
            self.condition.wait(millis_to_seconds(timeout))

    def notify_all(self) -> None:
        """Notifies all waiting threads"""
        with self.condition:
            self.condition.notify_all()
            for listener in self._notify_listeners:
                listener.notify_all()

    def get_service_info(self, type_: str, name: str, timeout: int = 3000) -> Optional[ServiceInfo]:
        """Returns network's service information for a particular
        name and type, or None if no service matches by the timeout,
        which defaults to 3 seconds."""
        info = ServiceInfo(type_, name)
        if info.request(self, timeout):
            return info
        return None

    def add_notify_listener(self, listener: NotifyListener) -> None:
        """Adds a listener to receive notify_all events."""
        self._notify_listeners.append(listener)

    def remove_notify_listener(self, listener: NotifyListener) -> None:
        """Removes a listener from the set that is currently listening."""
        self._notify_listeners.remove(listener)

    def add_service_listener(self, type_: str, listener: ServiceListener) -> None:
        """Adds a listener for a particular service type.  This object
        will then have its add_service and remove_service methods called when
        services of that type become available and unavailable."""
        self.remove_service_listener(listener)
        self.browsers[listener] = ServiceBrowser(self, type_, listener)

    def remove_service_listener(self, listener: ServiceListener) -> None:
        """Removes a listener from the set that is currently listening."""
        if listener in self.browsers:
            self.browsers[listener].cancel()
            del self.browsers[listener]

    def remove_all_service_listeners(self) -> None:
        """Removes a listener from the set that is currently listening."""
        for listener in list(self.browsers):
            self.remove_service_listener(listener)

    def register_service(
        self,
        info: ServiceInfo,
        ttl: Optional[int] = None,
        allow_name_change: bool = False,
        cooperating_responders: bool = False,
    ) -> None:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service.  The name of the service may be changed if needed to make
        it unique on the network. Additionally multiple cooperating responders
        can register the same service on the network for resilience
        (if you want this behavior set `cooperating_responders` to `True`)."""
        if ttl is not None:
            # ttl argument is used to maintain backward compatibility
            # Setting TTLs via ServiceInfo is preferred
            info.host_ttl = ttl
            info.other_ttl = ttl
        self.check_service(info, allow_name_change, cooperating_responders)
        self.registry.add(info)
        self._broadcast_service(info, _REGISTER_TIME, None)

    def update_service(self, info: ServiceInfo) -> None:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service."""

        self.registry.update(info)
        self._broadcast_service(info, _REGISTER_TIME, None)

    def _broadcast_service(self, info: ServiceInfo, interval: int, ttl: Optional[int]) -> None:
        """Send a broadcasts to announce a service at intervals."""
        now = current_time_millis()
        next_time = now
        i = 0
        while i < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue

            self.send_service_broadcast(info, ttl)
            i += 1
            next_time += interval

    def send_service_broadcast(self, info: ServiceInfo, ttl: Optional[int]) -> None:
        """Send a broadcast to announce a service."""
        self.send(self.generate_service_broadcast(info, ttl))

    def generate_service_broadcast(self, info: ServiceInfo, ttl: Optional[int]) -> DNSOutgoing:
        """Generate a broadcast to announce a service."""
        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
        self._add_broadcast_answer(out, info, ttl)
        return out

    def send_service_query(self, info: ServiceInfo) -> None:
        """Send a query to lookup a service."""
        self.send(self.generate_service_query(info))

    def generate_service_query(self, info: ServiceInfo) -> DNSOutgoing:  # pylint: disable=no-self-use
        """Generate a query to lookup a service."""
        out = DNSOutgoing(_FLAGS_QR_QUERY | _FLAGS_AA)
        out.add_question(DNSQuestion(info.type, _TYPE_PTR, _CLASS_IN))
        out.add_authorative_answer(info.dns_pointer())
        return out

    def _add_broadcast_answer(  # pylint: disable=no-self-use
        self, out: DNSOutgoing, info: ServiceInfo, override_ttl: Optional[int]
    ) -> None:
        """Add answers to broadcast a service."""
        other_ttl = info.other_ttl if override_ttl is None else override_ttl
        host_ttl = info.host_ttl if override_ttl is None else override_ttl
        out.add_answer_at_time(info.dns_pointer(override_ttl=other_ttl), 0)
        out.add_answer_at_time(info.dns_service(override_ttl=host_ttl), 0)
        out.add_answer_at_time(info.dns_text(override_ttl=other_ttl), 0)
        for dns_address in info.dns_addresses(override_ttl=host_ttl):
            out.add_answer_at_time(dns_address, 0)

    def unregister_service(self, info: ServiceInfo) -> None:
        """Unregister a service."""
        self.registry.remove(info)
        self._broadcast_service(info, _UNREGISTER_TIME, 0)

    def unregister_all_services(self) -> None:
        """Unregister all registered services."""
        service_infos = self.registry.get_service_infos()
        if not service_infos:
            return
        now = current_time_millis()
        next_time = now
        i = 0
        while i < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue
            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
            for info in service_infos:
                self._add_broadcast_answer(out, info, 0)
            self.send(out)
            i += 1
            next_time += _UNREGISTER_TIME

    def check_service(
        self, info: ServiceInfo, allow_name_change: bool, cooperating_responders: bool = False
    ) -> None:
        """Checks the network for a unique service name, modifying the
        ServiceInfo passed in if it is not unique."""
        instance_name = instance_name_from_service_info(info)
        if cooperating_responders:
            return
        next_instance_number = 2
        next_time = now = current_time_millis()
        i = 0
        while i < 3:
            # check for a name conflict
            while self.cache.current_entry_with_name_and_alias(info.type, info.name):
                if not allow_name_change:
                    raise NonUniqueNameException

                # change the name and look for a conflict
                info.name = '%s-%s.%s' % (instance_name, next_instance_number, info.type)
                next_instance_number += 1
                service_type_name(info.name)
                next_time = now
                i = 0

            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue

            self.send_service_query(info)
            i += 1
            next_time += _CHECK_TIME

    def add_listener(
        self, listener: RecordUpdateListener, question: Optional[Union[DNSQuestion, List[DNSQuestion]]]
    ) -> None:
        """Adds a listener for a given question.  The listener will have
        its update_record method called when information is available to
        answer the question(s)."""
        self.record_manager.add_listener(listener, question)

    def remove_listener(self, listener: RecordUpdateListener) -> None:
        """Removes a listener."""
        self.record_manager.remove_listener(listener)

    def handle_response(self, msg: DNSIncoming) -> None:
        """Deal with incoming response packets.  All answers
        are held in the cache, and listeners are notified."""
        self.record_manager.updates_from_response(msg)

    def handle_query(self, msg: DNSIncoming, addr: Optional[str], port: int) -> None:
        """Deal with incoming query packets.  Provides a response if
        possible."""
        out = self.query_handler.response(msg, port != _MDNS_PORT)
        if out:
            self.send(out, addr, port)

    def send(self, out: DNSOutgoing, addr: Optional[str] = None, port: int = _MDNS_PORT) -> None:
        """Sends an outgoing packet."""
        packets = out.packets()
        packet_num = 0
        for packet in packets:
            packet_num += 1
            if len(packet) > _MAX_MSG_ABSOLUTE:
                self.log_warning_once("Dropping %r over-sized packet (%d bytes) %r", out, len(packet), packet)
                return
            log.debug('Sending (%d bytes #%d) %r as %r...', len(packet), packet_num, out, packet)
            for s in self._respond_sockets:
                if self._GLOBAL_DONE:
                    return
                try:
                    if addr is None:
                        real_addr = _MDNS_ADDR6 if s.family == socket.AF_INET6 else _MDNS_ADDR
                    elif not can_send_to(s, addr):
                        continue
                    else:
                        real_addr = addr
                    bytes_sent = s.sendto(packet, 0, (real_addr, port))
                except OSError as exc:
                    if exc.errno == errno.ENETUNREACH and s.family == socket.AF_INET6:
                        # with IPv6 we don't have a reliable way to determine if an interface actually has
                        # IPV6 support, so we have to try and ignore errors.
                        continue
                    # on send errors, log the exception and keep going
                    self.log_exception_warning('Error sending through socket %d', s.fileno())
                except Exception:  # pylint: disable=broad-except  # TODO stop catching all Exceptions
                    # on send errors, log the exception and keep going
                    self.log_exception_warning('Error sending through socket %d', s.fileno())
                else:
                    if bytes_sent != len(packet):
                        self.log_warning_once('!!! sent %d of %d bytes to %r' % (bytes_sent, len(packet), s))

    def close(self) -> None:
        """Ends the background threads, and prevent this instance from
        servicing further queries."""
        if self._GLOBAL_DONE:
            return
        # remove service listeners
        self.remove_all_service_listeners()
        self.unregister_all_services()
        self._GLOBAL_DONE = True

        # shutdown recv socket and thread
        if not self.unicast:
            self.engine.del_reader(cast(socket.socket, self._listen_socket))
            cast(socket.socket, self._listen_socket).close()
        if self.multi_socket:
            for s in self._respond_sockets:
                self.engine.del_reader(s)
        self.engine.join()
        # shutdown the rest
        self.notify_all()
        for s in self._respond_sockets:
            s.close()

    def __enter__(self) -> 'Zeroconf':
        return self

    def __exit__(  # pylint: disable=useless-return
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Optional[bool]:
        self.close()
        return None
