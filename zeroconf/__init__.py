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
import logging
import platform
import re
import select
import socket
import struct
import sys
import threading
import time
import warnings
from collections import OrderedDict
from typing import Dict, Iterable, List, Optional, Union, cast
from typing import Any, Callable, Set, Tuple  # noqa # used in type hints

import ifaddr

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

if sys.version_info <= (3, 4):
    raise ImportError(
        '''
Python version > 3.4 required for python-zeroconf.
If you need support for Python 2 or Python 3.3-3.4 please use version 19.1
    '''
    )

log = logging.getLogger(__name__)
log.addHandler(logging.NullHandler())

if log.level == logging.NOTSET:
    log.setLevel(logging.WARN)

# Some timing constants

_UNREGISTER_TIME = 125  # ms
_CHECK_TIME = 175  # ms
_REGISTER_TIME = 225  # ms
_LISTENER_TIME = 200  # ms
_BROWSER_TIME = 1000  # ms
_BROWSER_BACKOFF_LIMIT = 3600  # s

# Some DNS constants

_MDNS_ADDR = '224.0.0.251'
_MDNS_ADDR_BYTES = socket.inet_aton(_MDNS_ADDR)
_MDNS_ADDR6 = 'ff02::fb'
_MDNS_ADDR6_BYTES = socket.inet_pton(socket.AF_INET6, _MDNS_ADDR6)
_MDNS_PORT = 5353
_DNS_PORT = 53
_DNS_HOST_TTL = 120  # two minute for host records (A, SRV etc) as-per RFC6762
_DNS_OTHER_TTL = 4500  # 75 minutes for non-host records (PTR, TXT etc) as-per RFC6762

_MAX_MSG_TYPICAL = 1460  # unused
_MAX_MSG_ABSOLUTE = 8966

_FLAGS_QR_MASK = 0x8000  # query response mask
_FLAGS_QR_QUERY = 0x0000  # query
_FLAGS_QR_RESPONSE = 0x8000  # response

_FLAGS_AA = 0x0400  # Authoritative answer
_FLAGS_TC = 0x0200  # Truncated
_FLAGS_RD = 0x0100  # Recursion desired
_FLAGS_RA = 0x8000  # Recursion available

_FLAGS_Z = 0x0040  # Zero
_FLAGS_AD = 0x0020  # Authentic data
_FLAGS_CD = 0x0010  # Checking disabled

_CLASS_IN = 1
_CLASS_CS = 2
_CLASS_CH = 3
_CLASS_HS = 4
_CLASS_NONE = 254
_CLASS_ANY = 255
_CLASS_MASK = 0x7FFF
_CLASS_UNIQUE = 0x8000

_TYPE_A = 1
_TYPE_NS = 2
_TYPE_MD = 3
_TYPE_MF = 4
_TYPE_CNAME = 5
_TYPE_SOA = 6
_TYPE_MB = 7
_TYPE_MG = 8
_TYPE_MR = 9
_TYPE_NULL = 10
_TYPE_WKS = 11
_TYPE_PTR = 12
_TYPE_HINFO = 13
_TYPE_MINFO = 14
_TYPE_MX = 15
_TYPE_TXT = 16
_TYPE_AAAA = 28
_TYPE_SRV = 33
_TYPE_ANY = 255

# Mapping constants to names

_CLASSES = {
    _CLASS_IN: "in",
    _CLASS_CS: "cs",
    _CLASS_CH: "ch",
    _CLASS_HS: "hs",
    _CLASS_NONE: "none",
    _CLASS_ANY: "any",
}

_TYPES = {
    _TYPE_A: "a",
    _TYPE_NS: "ns",
    _TYPE_MD: "md",
    _TYPE_MF: "mf",
    _TYPE_CNAME: "cname",
    _TYPE_SOA: "soa",
    _TYPE_MB: "mb",
    _TYPE_MG: "mg",
    _TYPE_MR: "mr",
    _TYPE_NULL: "null",
    _TYPE_WKS: "wks",
    _TYPE_PTR: "ptr",
    _TYPE_HINFO: "hinfo",
    _TYPE_MINFO: "minfo",
    _TYPE_MX: "mx",
    _TYPE_TXT: "txt",
    _TYPE_AAAA: "quada",
    _TYPE_SRV: "srv",
    _TYPE_ANY: "any",
}

_HAS_A_TO_Z = re.compile(r'[A-Za-z]')
_HAS_ONLY_A_TO_Z_NUM_HYPHEN = re.compile(r'^[A-Za-z0-9\-]+$')
_HAS_ONLY_A_TO_Z_NUM_HYPHEN_UNDERSCORE = re.compile(r'^[A-Za-z0-9\-\_]+$')
_HAS_ASCII_CONTROL_CHARS = re.compile(r'[\x00-\x1f\x7f]')

_EXPIRE_FULL_TIME_PERCENT = 100
_EXPIRE_STALE_TIME_PERCENT = 50
_EXPIRE_REFRESH_TIME_PERCENT = 75

_LOCAL_TRAILER = '.local.'
_TCP_PROTOCOL_LOCAL_TRAILER = '._tcp.local.'
_NONTCP_PROTOCOL_LOCAL_TRAILER = '._udp.local.'

try:
    _IPPROTO_IPV6 = socket.IPPROTO_IPV6
except AttributeError:
    # Sigh: https://bugs.python.org/issue29515
    _IPPROTO_IPV6 = 41

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


def _is_v6_address(addr: bytes) -> bool:
    return len(addr) == 16


def _encode_address(address: str) -> bytes:
    is_ipv6 = ':' in address
    address_family = socket.AF_INET6 if is_ipv6 else socket.AF_INET
    return socket.inet_pton(address_family, address)


def service_type_name(type_: str, *, strict: bool = True) -> str:
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

    if type_.endswith(_TCP_PROTOCOL_LOCAL_TRAILER) or type_.endswith(_NONTCP_PROTOCOL_LOCAL_TRAILER):
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


# Exceptions


class Error(Exception):
    pass


class IncomingDecodeError(Error):
    pass


class NonUniqueNameException(Error):
    pass


class NamePartTooLongException(Error):
    pass


class AbstractMethodException(Error):
    pass


class BadTypeInNameException(Error):
    pass


class ServiceNameAlreadyRegistered(Error):
    pass


# implementation classes


class QuietLogger:
    _seen_logs = {}  # type: Dict[str, Union[int, tuple]]

    @classmethod
    def log_exception_warning(cls, *logger_data: Any) -> None:
        exc_info = sys.exc_info()
        exc_str = str(exc_info[1])
        if exc_str not in cls._seen_logs:
            # log at warning level the first time this is seen
            cls._seen_logs[exc_str] = exc_info
            logger = log.warning
        else:
            logger = log.debug
        logger(*(logger_data or ['Exception occurred']), exc_info=True)

    @classmethod
    def log_warning_once(cls, *args: Any) -> None:
        msg_str = args[0]
        if msg_str not in cls._seen_logs:
            cls._seen_logs[msg_str] = 0
            logger = log.warning
        else:
            logger = log.debug
        cls._seen_logs[msg_str] = cast(int, cls._seen_logs[msg_str]) + 1
        logger(*args)


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

    def __ne__(self, other: Any) -> bool:
        """Non-equality test"""
        return not self.__eq__(other)

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

    def __eq__(self, other: Any) -> bool:
        """Abstract method"""
        raise AbstractMethodException

    def __ne__(self, other: Any) -> bool:
        """Non-equality test"""
        return not self.__eq__(other)

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
        return max(0, (self._expiration_time - now) / 1000.0)

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

    def write(self, out: 'DNSOutgoing') -> None:
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

    def __ne__(self, other: Any) -> bool:
        """Non-equality test"""
        return not self.__eq__(other)

    def __repr__(self) -> str:
        """String representation"""
        try:
            return self.to_string(
                socket.inet_ntop(
                    socket.AF_INET6 if _is_v6_address(self.address) else socket.AF_INET, self.address
                )
            )
        except Exception:  # TODO stop catching all Exceptions
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

    def __ne__(self, other: Any) -> bool:
        """Non-equality test"""
        return not self.__eq__(other)

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

    def __ne__(self, other: Any) -> bool:
        """Non-equality test"""
        return not self.__eq__(other)

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

    def __ne__(self, other: Any) -> bool:
        """Non-equality test"""
        return not self.__eq__(other)

    def __repr__(self) -> str:
        """String representation"""
        if len(self.text) > 10:
            return self.to_string(self.text[:7]) + "..."
        else:
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

    def __ne__(self, other: Any) -> bool:
        """Non-equality test"""
        return not self.__eq__(other)

    def __repr__(self) -> str:
        """String representation"""
        return self.to_string("%s:%s" % (self.server, self.port))


class DNSIncoming(QuietLogger):

    """Object representation of an incoming DNS packet"""

    def __init__(self, data: bytes) -> None:
        """Constructor from string holding bytes of packet"""
        self.offset = 0
        self.data = data
        self.questions = []  # type: List[DNSQuestion]
        self.answers = []  # type: List[DNSRecord]
        self.id = 0
        self.flags = 0  # type: int
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
        for i in range(self.num_questions):
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
        for i in range(n):
            domain = self.read_name()
            type_, class_, ttl, length = self.unpack(b'!HHiH')

            rec = None  # type: Optional[DNSRecord]
            if type_ == _TYPE_A:
                rec = DNSAddress(domain, type_, class_, ttl, self.read_string(4))
            elif type_ == _TYPE_CNAME or type_ == _TYPE_PTR:
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

    def is_query(self) -> bool:
        """Returns true if this is a query"""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_QUERY

    def is_response(self) -> bool:
        """Returns true if this is a response"""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_RESPONSE

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


class DNSOutgoing:

    """Object representation of an outgoing packet"""

    def __init__(self, flags: int, multicast: bool = True) -> None:
        self.finished = False
        self.id = 0
        self.multicast = multicast
        self.flags = flags
        self.packets_data = []  # type: List[bytes]

        # these 3 are per-packet -- see also reset_for_next_packet()
        self.names = {}  # type: Dict[str, int]
        self.data = []  # type: List[bytes]
        self.size = 12

        self.state = self.State.init

        self.questions = []  # type: List[DNSQuestion]
        self.answers = []  # type: List[Tuple[DNSRecord, float]]
        self.authorities = []  # type: List[DNSPointer]
        self.additionals = []  # type: List[DNSRecord]

    def reset_for_next_packet(self) -> None:
        self.names = {}
        self.data = []
        self.size = 12

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

    @staticmethod
    def is_type_unique(type_: int) -> bool:
        return type_ == _TYPE_TXT or type_ == _TYPE_SRV or type_ == _TYPE_A or type_ == _TYPE_AAAA

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

    def write_question(self, question: DNSQuestion) -> None:
        """Writes a question to the packet"""
        self.write_name(question.name)
        self.write_short(question.type)
        self.write_short(question.class_)

    def write_record(self, record: DNSRecord, now: float, allow_long: bool = False) -> bool:
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
        len_limit = _MAX_MSG_ABSOLUTE if allow_long else _MAX_MSG_TYPICAL

        # if we go over, then rollback and quit
        if self.size > len_limit:
            while len(self.data) > start_data_length:
                self.data.pop()
            self.size = start_size

            rollback_names = [name for name, idx in self.names.items() if idx >= start_size]
            for name in rollback_names:
                del self.names[name]
            return False
        return True

    def packet(self) -> bytes:
        """Returns a bytestring containing the first packet's bytes.

        Generally, you want to use packets() in case the response
        does not fit in a single packet, but this exists for
        backward compatibility."""
        packets = self.packets()
        if len(packets) > 0:
            if len(packets[0]) > _MAX_MSG_ABSOLUTE:
                QuietLogger.log_warning_once(
                    "Created over-sized packet (%d bytes) %r", len(packets[0]), packets[0]
                )
            return packets[0]
        else:
            return b''

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

        answer_offset = 0
        authority_offset = 0
        additional_offset = 0

        # we have to at least write out the question
        first_time = True

        while (
            first_time
            or answer_offset < len(self.answers)
            or authority_offset < len(self.authorities)
            or additional_offset < len(self.additionals)
        ):
            first_time = False
            log.debug("offsets = %d, %d, %d", answer_offset, authority_offset, additional_offset)
            log.debug("lengths = %d, %d, %d", len(self.answers), len(self.authorities), len(self.additionals))

            additionals_written = 0
            authorities_written = 0
            answers_written = 0
            questions_written = 0
            for question in self.questions:
                self.write_question(question)
                questions_written += 1
            allow_long = True  # at most one answer is allowed to be a long packet
            for answer, time_ in self.answers[answer_offset:]:
                if self.write_record(answer, time_, allow_long):
                    answers_written += 1
                allow_long = False
            for authority in self.authorities[authority_offset:]:
                if self.write_record(authority, 0):
                    authorities_written += 1
            for additional in self.additionals[additional_offset:]:
                if self.write_record(additional, 0):
                    additionals_written += 1

            self.insert_short_at_start(additionals_written)
            self.insert_short_at_start(authorities_written)
            self.insert_short_at_start(answers_written)
            self.insert_short_at_start(questions_written)
            self.insert_short_at_start(self.flags)
            if self.multicast:
                self.insert_short_at_start(0)
            else:
                self.insert_short_at_start(self.id)
            self.packets_data.append(b''.join(self.data))
            self.reset_for_next_packet()

            answer_offset += answers_written
            authority_offset += authorities_written
            additional_offset += additionals_written
            log.debug("now offsets = %d, %d, %d", answer_offset, authority_offset, additional_offset)
            if (answers_written + authorities_written + additionals_written) == 0 and (
                len(self.answers) + len(self.authorities) + len(self.additionals)
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

    def remove(self, entry: DNSRecord) -> None:
        """Removes an entry."""
        if isinstance(entry, DNSService):
            DNSCache.remove_key(self.service_cache, entry.server, entry)
        DNSCache.remove_key(self.cache, entry.key, entry)

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
        try:
            list_ = self.cache[entry.key]
            for cached_entry in reversed(list_):
                if entry.__eq__(cached_entry):
                    return cached_entry
            return None
        except (KeyError, ValueError):
            return None

    def get_by_details(self, name: str, type_: int, class_: int) -> Optional[DNSRecord]:
        """Gets an entry by details.  Will return None if there is
        no matching entry."""
        entry = DNSEntry(name, type_, class_)
        return self.get(entry)

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
        self.cache_cleanup_interval_ms = 10000.0
        self.condition = threading.Condition()
        self.socketpair = socket.socketpair()
        self._last_cache_cleanup = 0.0
        self.start()
        self.name = "zeroconf-Engine-%s" % (getattr(self, 'native_id', self.ident),)

    def run(self) -> None:
        while not self.zc.done:
            rs = list(self.readers.keys())
            if not rs:
                # No sockets to manage, but we wait for the timeout
                # or addition of a socket
                with self.condition:
                    self.condition.wait(self.timeout)
                continue

            try:
                rs.append(self.socketpair[0])
                rr, wr, er = select.select(rs, [], [], self.timeout)

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
            if now - self._last_cache_cleanup >= self.cache_cleanup_interval_ms:
                self._last_cache_cleanup = now
                for record in self.zc.cache.expire(now):
                    self.zc.update_record(now, record)

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
        except Exception:
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


# NOTE: Callable quoting needed on Python 3.5.2, see
# https://github.com/jstasiak/python-zeroconf/issues/208 for details.
class SignalRegistrationInterface:
    def __init__(self, handlers: List['Callable[..., None]']) -> None:
        self._handlers = handlers

    def register_handler(self, handler: 'Callable[..., None]') -> 'SignalRegistrationInterface':
        self._handlers.append(handler)
        return self

    def unregister_handler(self, handler: 'Callable[..., None]') -> 'SignalRegistrationInterface':
        self._handlers.remove(handler)
        return self


class RecordUpdateListener:
    def update_record(self, zc: 'Zeroconf', now: float, record: DNSRecord) -> None:
        raise NotImplementedError()


class ServiceListener:
    def add_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()

    def remove_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()

    def update_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()


class ServiceBrowser(RecordUpdateListener, threading.Thread):

    """Used to browse for a service of a specific type.

    The listener object will have its add_service() and
    remove_service() methods called when this browser
    discovers changes in the services availability."""

    def __init__(
        self,
        zc: 'Zeroconf',
        type_: Union[str, list],
        # NOTE: Callable quoting needed on Python 3.5.2, see
        # https://github.com/jstasiak/python-zeroconf/issues/208 for details.
        handlers: Optional[Union[ServiceListener, List['Callable[..., None]']]] = None,
        listener: Optional[ServiceListener] = None,
        addr: Optional[str] = None,
        port: int = _MDNS_PORT,
        delay: int = _BROWSER_TIME,
    ) -> None:
        """Creates a browser for a specific type"""
        assert handlers or listener, 'You need to specify at least one handler'
        self.types = set(type_ if isinstance(type_, list) else [type_])
        for check_type_ in self.types:
            if not check_type_.endswith(service_type_name(check_type_, strict=False)):
                raise BadTypeInNameException
        threading.Thread.__init__(self)
        self.daemon = True
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
        self._handlers_to_call = OrderedDict()  # type: OrderedDict[str, Tuple[str, ServiceStateChange]]

        self._service_state_changed = Signal()

        self.done = False

        if hasattr(handlers, 'add_service'):
            listener = cast(ServiceListener, handlers)
            handlers = None

        # NOTE: Callable quoting needed on Python 3.5.2, see
        # https://github.com/jstasiak/python-zeroconf/issues/208 for details.
        handlers = cast(List['Callable[..., None]'], handlers or [])

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

        self.start()
        self.name = "zeroconf-ServiceBrowser_%s_%s" % (
            '-'.join(self.types),
            getattr(self, 'native_id', self.ident),
        )

    @property
    def service_state_changed(self) -> SignalRegistrationInterface:
        return self._service_state_changed.registration_interface

    def update_record(self, zc: 'Zeroconf', now: float, record: DNSRecord) -> None:
        """Callback invoked by Zeroconf when new information arrives.

        Updates information required by browser in the Zeroconf cache.

        Ensures that there is are no unecessary duplicates in the list

        """

        def enqueue_callback(state_change: ServiceStateChange, type_: str, name: str) -> None:

            # Code to ensure we only do a single update message
            # Precedence is; Added, Remove, Update

            if (
                state_change is ServiceStateChange.Added
                or (
                    state_change is ServiceStateChange.Removed
                    and (
                        self._handlers_to_call.get(name) is ServiceStateChange.Updated
                        or self._handlers_to_call.get(name) is ServiceStateChange.Added
                        or self._handlers_to_call.get(name) is None
                    )
                )
                or (state_change is ServiceStateChange.Updated and name not in self._handlers_to_call)
            ):
                self._handlers_to_call[name] = (type_, state_change)

        if record.type == _TYPE_PTR and record.name in self.types:
            assert isinstance(record, DNSPointer)
            expired = record.is_expired(now)
            service_key = record.alias.lower()
            try:
                old_record = self._services[record.name][service_key]
            except KeyError:
                if not expired:
                    self._services[record.name][service_key] = record
                    enqueue_callback(ServiceStateChange.Added, record.name, record.alias)
            else:
                if not expired:
                    old_record.reset_ttl(record)
                else:
                    del self._services[record.name][service_key]
                    enqueue_callback(ServiceStateChange.Removed, record.name, record.alias)
                    return

            expires = record.get_expiration_time(_EXPIRE_REFRESH_TIME_PERCENT)
            if expires < self._next_time[record.name]:
                self._next_time[record.name] = expires

        elif record.type == _TYPE_A or record.type == _TYPE_AAAA:
            assert isinstance(record, DNSAddress)
            if record.is_expired(now):
                return

            address_changed = False
            for service in zc.cache.entries_with_name(record.name):
                if isinstance(service, DNSAddress) and service.address != record.address:
                    address_changed = True
                    break

            # Avoid iterating the entire DNSCache if the address has not changed
            # as this is an expensive operation when there many hosts
            # generating zeroconf traffic.
            if not address_changed:
                return

            # Iterate through the DNSCache and callback any services that use this address
            for service in self.zc.cache.entries_with_server(record.name):
                for type_ in self.types:
                    if service.name.endswith(type_):
                        enqueue_callback(ServiceStateChange.Updated, type_, service.name)

        elif not record.is_expired(now):
            for type_ in self.types:
                if record.name.endswith(type_):
                    enqueue_callback(ServiceStateChange.Updated, type_, record.name)

    def cancel(self) -> None:
        self.done = True
        self.zc.remove_listener(self)
        self.join()

    def run(self) -> None:
        questions = [DNSQuestion(type_, _TYPE_PTR, _CLASS_IN) for type_ in self.types]
        self.zc.add_listener(self, questions)

        while True:
            now = current_time_millis()
            # Wait for the type has the smallest next time
            next_time = min(self._next_time.values())
            if len(self._handlers_to_call) == 0 and next_time > now:
                self.zc.wait(next_time - now)
            if self.zc.done or self.done:
                return
            now = current_time_millis()
            for type_ in self.types:
                if self._next_time[type_] > now:
                    continue
                out = DNSOutgoing(_FLAGS_QR_QUERY, multicast=self.multicast)
                out.add_question(DNSQuestion(type_, _TYPE_PTR, _CLASS_IN))
                for record in self._services[type_].values():
                    if not record.is_stale(now):
                        out.add_answer_at_time(record, now)

                self.zc.send(out, addr=self.addr, port=self.port)
                self._next_time[type_] = now + self._delay[type_]
                self._delay[type_] = min(_BROWSER_BACKOFF_LIMIT * 1000, self._delay[type_] * 2)

            if len(self._handlers_to_call) > 0 and not self.zc.done:
                with self.zc._handlers_lock:
                    (name, service_type_state_change) = self._handlers_to_call.popitem(False)
                self._service_state_changed.fire(
                    zeroconf=self.zc,
                    service_type=service_type_state_change[0],
                    name=name,
                    state_change=service_type_state_change[1],
                )


class ServiceInfo(RecordUpdateListener):
    """Service information.

    Constructor parameters are as follows:

    * type_: fully qualified service type name
    * name: fully qualified service name
    * port: port that the service runs on
    * weight: weight of the service
    * priority: priority of the service
    * properties: dictionary of properties (or a bytes object holding the contents of the `text` field).
      converted to str and then encoded to bytes using UTF-8. Keys with `None` values are converted to
      value-less attributes.
    * server: fully qualified name for service host (defaults to name)
    * host_ttl: ttl used for A/SRV records
    * other_ttl: ttl used for PTR/TXT records
    * addresses and parsed_addresses: List of IP addresses (either as bytes, network byte order, or in parsed
      form as text; at most one of those parameters can be provided)

    """

    text = b''

    # FIXME(dtantsur): black 19.3b0 produces code that is not valid syntax on
    # Python 3.5: https://github.com/python/black/issues/759
    # fmt: off
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
        invalid = [a for a in self._addresses
                   if not isinstance(a, bytes) or len(a) not in (4, 16)]
        if invalid:
            raise TypeError('Addresses must be bytes, got %s. Hint: convert string addresses '
                            'with socket.inet_pton' % invalid)
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
    # fmt: on

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
        elif version == IPVersion.V6Only:
            return list(filter(_is_v6_address, self._addresses))
        else:
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
        if self.type is not None and self.name.endswith("." + self.type):
            return self.name[: len(self.name) - len(self.type) - 1]
        return self.name

    def update_record(self, zc: 'Zeroconf', now: float, record: Optional[DNSRecord]) -> None:
        """Updates service information from a DNS record"""
        if record is not None and not record.is_expired(now):
            if record.type in [_TYPE_A, _TYPE_AAAA]:
                assert isinstance(record, DNSAddress)
                if record.key == self.server_key:
                    if record.address not in self._addresses:
                        self._addresses.append(record.address)
            elif record.type == _TYPE_SRV:
                assert isinstance(record, DNSService)
                if record.key == self.key:
                    self.name = record.name
                    self.server = record.server
                    self.server_key = record.server.lower()
                    self.port = record.port
                    self.weight = record.weight
                    self.priority = record.priority
                    self.update_record(zc, now, zc.cache.get_by_details(self.server, _TYPE_A, _CLASS_IN))
                    self.update_record(zc, now, zc.cache.get_by_details(self.server, _TYPE_AAAA, _CLASS_IN))
            elif record.type == _TYPE_TXT:
                assert isinstance(record, DNSText)
                if record.key == self.key:
                    self._set_text(record.text)

    def load_from_cache(self, zc: 'Zeroconf') -> bool:
        """Populate the service info from the cache."""
        now = current_time_millis()
        record_types_for_check_cache = [(_TYPE_SRV, _CLASS_IN), (_TYPE_TXT, _CLASS_IN)]
        if self.server is not None:
            record_types_for_check_cache.append((_TYPE_A, _CLASS_IN))
            record_types_for_check_cache.append((_TYPE_AAAA, _CLASS_IN))
        for record_type in record_types_for_check_cache:
            cached = zc.cache.get_by_details(self.name, *record_type)
            if cached:
                self.update_record(zc, now, cached)

        if self.server is not None and self.text is not None and self._addresses:
            return True
        return False

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
            zc.add_listener(self, DNSQuestion(self.name, _TYPE_ANY, _CLASS_IN))
            while self.server is None or self.text is None or not self._addresses:
                if last <= now:
                    return False
                if next_ <= now:
                    out = DNSOutgoing(_FLAGS_QR_QUERY)
                    cached_entry = zc.cache.get_by_details(self.name, _TYPE_SRV, _CLASS_IN)
                    if not cached_entry:
                        out.add_question(DNSQuestion(self.name, _TYPE_SRV, _CLASS_IN))
                        out.add_answer_at_time(cached_entry, now)
                    cached_entry = zc.cache.get_by_details(self.name, _TYPE_TXT, _CLASS_IN)
                    if not cached_entry:
                        out.add_question(DNSQuestion(self.name, _TYPE_TXT, _CLASS_IN))
                        out.add_answer_at_time(cached_entry, now)

                    if self.server is not None:
                        cached_entry = zc.cache.get_by_details(self.server, _TYPE_A, _CLASS_IN)
                        if not cached_entry:
                            out.add_question(DNSQuestion(self.server, _TYPE_A, _CLASS_IN))
                            out.add_answer_at_time(cached_entry, now)
                        cached_entry = zc.cache.get_by_details(self.name, _TYPE_AAAA, _CLASS_IN)
                        if not cached_entry:
                            out.add_question(DNSQuestion(self.server, _TYPE_AAAA, _CLASS_IN))
                            out.add_answer_at_time(cached_entry, now)
                    zc.send(out)
                    next_ = now + delay
                    delay *= 2

                zc.wait(min(next_, last) - now)
                now = current_time_millis()
        finally:
            zc.remove_listener(self)

        return True

    def __eq__(self, other: object) -> bool:
        """Tests equality of service name"""
        return isinstance(other, ServiceInfo) and other.name == self.name

    def __ne__(self, other: object) -> bool:
        """Non-equality test"""
        return not self.__eq__(other)

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
        self.found_services = set()  # type: Set[str]

    def add_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        self.found_services.add(name)

    def remove_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        pass

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
        browser = ServiceBrowser(local_zc, '_services._dns-sd._udp.local.', listener=listener)

        # wait for responses
        time.sleep(timeout)

        # close down anything we opened
        if zc is None:
            local_zc.close()
        else:
            browser.cancel()

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


def new_socket(
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
            if not err.errno == errno.ENOPROTOOPT:
                raise

    if port == _MDNS_PORT:
        ttl = struct.pack(b'B', 255)
        loop = struct.pack(b'B', 1)
        if ip_version != IPVersion.V6Only:
            # OpenBSD needs the ttl and loop values for the IP_MULTICAST_TTL and
            # IP_MULTICAST_LOOP socket options as an unsigned char.
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, ttl)
            s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_LOOP, loop)
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
        err_einval |= {cast(Any, errno).WSAEINVAL}
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
        elif _errno == errno.EADDRNOTAVAIL:
            log.info(
                'Address not available when adding %s to multicast '
                'group, it is expected to happen on some systems',
                interface,
            )
            return False
        elif _errno in err_einval:
            log.info('Interface of %s does not support multicast, ' 'it is expected in WSL', interface)
            return False
        else:
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
        if ip_version is None and isinstance(interfaces, list):
            has_v6 = any(
                isinstance(i, int) or (isinstance(i, str) and ipaddress.ip_address(i).version == 6)
                for i in interfaces
            )
            has_v4 = any(isinstance(i, str) and ipaddress.ip_address(i).version == 4 for i in interfaces)
            if has_v4 and has_v6:
                ip_version = IPVersion.All
            elif has_v6:
                ip_version = IPVersion.V6Only

        if ip_version is None:
            ip_version = IPVersion.V4Only

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

        self.listeners = []  # type: List[RecordUpdateListener]
        self.browsers = {}  # type: Dict[ServiceListener, ServiceBrowser]
        self.registry = ServiceRegistry()

        self.cache = DNSCache()

        self.condition = threading.Condition()

        # Ensure we create the lock before
        # we add the listener as we could get
        # a message before the lock is created.
        self._handlers_lock = threading.Lock()  # ensure we process a full message in one go

        self.engine = Engine(self)
        self.listener = Listener(self)
        if not unicast:
            self.engine.add_reader(self.listener, cast(socket.socket, self._listen_socket))
        if self.multi_socket:
            for s in self._respond_sockets:
                self.engine.add_reader(self.listener, s)

    @property
    def done(self) -> bool:
        return self._GLOBAL_DONE

    def wait(self, timeout: float) -> None:
        """Calling thread waits for a given number of milliseconds or
        until notified."""
        with self.condition:
            self.condition.wait(timeout / 1000.0)

    def notify_all(self) -> None:
        """Notifies all waiting threads"""
        with self.condition:
            self.condition.notify_all()

    def get_service_info(self, type_: str, name: str, timeout: int = 3000) -> Optional[ServiceInfo]:
        """Returns network's service information for a particular
        name and type, or None if no service matches by the timeout,
        which defaults to 3 seconds."""
        info = ServiceInfo(type_, name)
        if info.request(self, timeout):
            return info
        return None

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
        for listener in [k for k in self.browsers]:
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
        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
        self._add_broadcast_answer(out, info, ttl)
        self.send(out)

    def send_service_query(self, info: ServiceInfo) -> None:
        """Send a query to lookup a service."""
        out = DNSOutgoing(_FLAGS_QR_QUERY | _FLAGS_AA)
        out.add_question(DNSQuestion(info.type, _TYPE_PTR, _CLASS_IN))
        out.add_authorative_answer(DNSPointer(info.type, _TYPE_PTR, _CLASS_IN, info.other_ttl, info.name))
        self.send(out)

    def _add_broadcast_answer(self, out: DNSOutgoing, info: ServiceInfo, override_ttl: Optional[int]) -> None:
        """Add answers to broadcast a service."""
        other_ttl = info.other_ttl if override_ttl is None else override_ttl
        host_ttl = info.host_ttl if override_ttl is None else override_ttl
        out.add_answer_at_time(DNSPointer(info.type, _TYPE_PTR, _CLASS_IN, other_ttl, info.name), 0)
        out.add_answer_at_time(
            DNSService(
                info.name,
                _TYPE_SRV,
                _CLASS_IN | _CLASS_UNIQUE,
                host_ttl,
                info.priority,
                info.weight,
                cast(int, info.port),
                info.server,
            ),
            0,
        )

        out.add_answer_at_time(
            DNSText(info.name, _TYPE_TXT, _CLASS_IN | _CLASS_UNIQUE, other_ttl, info.text), 0
        )
        for address in info.addresses_by_version(IPVersion.All):
            type_ = _TYPE_AAAA if _is_v6_address(address) else _TYPE_A
            out.add_answer_at_time(
                DNSAddress(info.server, type_, _CLASS_IN | _CLASS_UNIQUE, host_ttl, address), 0
            )

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
        now = current_time_millis()
        self.listeners.append(listener)
        if question is not None:
            questions = [question] if isinstance(question, DNSQuestion) else question
            for single_question in questions:
                for record in self.cache.entries_with_name(single_question.name):
                    if single_question.answered_by(record) and not record.is_expired(now):
                        listener.update_record(self, now, record)
        self.notify_all()

    def remove_listener(self, listener: RecordUpdateListener) -> None:
        """Removes a listener."""
        try:
            self.listeners.remove(listener)
            self.notify_all()
        except Exception as e:  # TODO stop catching all Exceptions
            log.exception('Unknown error, possibly benign: %r', e)

    def update_record(self, now: float, rec: DNSRecord) -> None:
        """Used to notify listeners of new information that has updated
        a record."""
        for listener in self.listeners:
            listener.update_record(self, now, rec)
        self.notify_all()

    def handle_response(self, msg: DNSIncoming) -> None:
        """Deal with incoming response packets.  All answers
        are held in the cache, and listeners are notified."""
        updates = []  # type: List[Tuple[float, DNSRecord, Optional[DNSRecord]]]
        now = current_time_millis()
        for record in msg.answers:

            updated = True

            if record.unique:  # https://tools.ietf.org/html/rfc6762#section-10.2
                # Since the cache format is keyed on the lower case record name
                # we can avoid iterating everything in the cache and
                # only look though entries for the specific name.
                # entries_with_name will take care of converting to lowercase
                for entry in self.cache.entries_with_name(record.name):

                    if entry == record:
                        updated = False

                    # Check the time first because it is far cheaper
                    # than the __eq__
                    if (record.created - entry.created > 1000) and DNSEntry.__eq__(entry, record):
                        self.cache.remove(entry)

            expired = record.is_expired(now)
            maybe_entry = self.cache.get(record)
            if not expired:
                if maybe_entry is not None:
                    maybe_entry.reset_ttl(record)
                else:
                    self.cache.add(record)
                if updated:
                    updates.append((now, record, None))
            elif maybe_entry is not None:
                updates.append((now, record, maybe_entry))

        if not updates:
            return

        # Only hold the lock if we have updates
        with self._handlers_lock:
            for update in updates:
                now, record, entry_to_remove = update
                self.update_record(update[0], update[1])
                if entry_to_remove:
                    self.cache.remove(entry_to_remove)

    def handle_query(self, msg: DNSIncoming, addr: Optional[str], port: int) -> None:
        """Deal with incoming query packets.  Provides a response if
        possible."""
        out = None

        # Support unicast client responses
        #
        if port != _MDNS_PORT:
            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA, multicast=False)
            for question in msg.questions:
                out.add_question(question)

        for question in msg.questions:
            if question.type == _TYPE_PTR:
                if question.name == "_services._dns-sd._udp.local.":
                    for stype in self.registry.get_types():
                        if out is None:
                            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
                        out.add_answer(
                            msg,
                            DNSPointer(
                                "_services._dns-sd._udp.local.",
                                _TYPE_PTR,
                                _CLASS_IN,
                                _DNS_OTHER_TTL,
                                stype,
                            ),
                        )
                for service in self.registry.get_infos_type(question.name):
                    if out is None:
                        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
                    out.add_answer(
                        msg,
                        DNSPointer(service.type, _TYPE_PTR, _CLASS_IN, service.other_ttl, service.name),
                    )

                    # Add recommended additional answers according to
                    # https://tools.ietf.org/html/rfc6763#section-12.1.
                    out.add_additional_answer(
                        DNSService(
                            service.name,
                            _TYPE_SRV,
                            _CLASS_IN | _CLASS_UNIQUE,
                            service.host_ttl,
                            service.priority,
                            service.weight,
                            cast(int, service.port),
                            service.server,
                        )
                    )
                    out.add_additional_answer(
                        DNSText(
                            service.name,
                            _TYPE_TXT,
                            _CLASS_IN | _CLASS_UNIQUE,
                            service.other_ttl,
                            service.text,
                        )
                    )
                    for address in service.addresses_by_version(IPVersion.All):
                        type_ = _TYPE_AAAA if _is_v6_address(address) else _TYPE_A
                        out.add_additional_answer(
                            DNSAddress(
                                service.server,
                                type_,
                                _CLASS_IN | _CLASS_UNIQUE,
                                service.host_ttl,
                                address,
                            )
                        )
            else:
                if out is None:
                    out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)

                name_to_find = question.name.lower()

                # Answer A record queries for any service addresses we know
                if question.type in (_TYPE_A, _TYPE_ANY):
                    for service in self.registry.get_infos_server(name_to_find):
                        for address in service.addresses_by_version(IPVersion.All):
                            type_ = _TYPE_AAAA if _is_v6_address(address) else _TYPE_A
                            out.add_answer(
                                msg,
                                DNSAddress(
                                    question.name,
                                    type_,
                                    _CLASS_IN | _CLASS_UNIQUE,
                                    service.host_ttl,
                                    address,
                                ),
                            )

                service = self.registry.get_info_name(name_to_find)  # type: ignore
                if service is None:
                    continue

                if question.type in (_TYPE_SRV, _TYPE_ANY):
                    out.add_answer(
                        msg,
                        DNSService(
                            question.name,
                            _TYPE_SRV,
                            _CLASS_IN | _CLASS_UNIQUE,
                            service.host_ttl,
                            service.priority,
                            service.weight,
                            cast(int, service.port),
                            service.server,
                        ),
                    )
                if question.type in (_TYPE_TXT, _TYPE_ANY):
                    out.add_answer(
                        msg,
                        DNSText(
                            question.name,
                            _TYPE_TXT,
                            _CLASS_IN | _CLASS_UNIQUE,
                            service.other_ttl,
                            service.text,
                        ),
                    )
                if question.type == _TYPE_SRV:
                    for address in service.addresses_by_version(IPVersion.All):
                        type_ = _TYPE_AAAA if _is_v6_address(address) else _TYPE_A
                        out.add_additional_answer(
                            DNSAddress(
                                service.server,
                                type_,
                                _CLASS_IN | _CLASS_UNIQUE,
                                service.host_ttl,
                                address,
                            )
                        )

        if out is not None and out.answers:
            out.id = msg.id
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
                except Exception as exc:  # TODO stop catching all Exceptions
                    if (
                        isinstance(exc, OSError)
                        and exc.errno == errno.ENETUNREACH
                        and s.family == socket.AF_INET6
                    ):
                        # with IPv6 we don't have a reliable way to determine if an interface actually has
                        # IPV6 support, so we have to try and ignore errors.
                        continue
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
