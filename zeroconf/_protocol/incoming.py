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

import struct
from typing import Callable, Dict, List, Optional, Set, Tuple, cast

from . import DNSMessage
from .._dns import DNSAddress, DNSHinfo, DNSNsec, DNSPointer, DNSQuestion, DNSRecord, DNSService, DNSText
from .._exceptions import IncomingDecodeError
from .._logger import QuietLogger, log
from .._utils.time import current_time_millis
from ..const import (
    _TYPES,
    _TYPE_A,
    _TYPE_AAAA,
    _TYPE_CNAME,
    _TYPE_HINFO,
    _TYPE_NSEC,
    _TYPE_PTR,
    _TYPE_SRV,
    _TYPE_TXT,
)

DNS_COMPRESSION_HEADER_LEN = 1
DNS_COMPRESSION_POINTER_LEN = 2
MAX_DNS_LABELS = 128
MAX_NAME_LENGTH = 253

DECODE_EXCEPTIONS = (IndexError, struct.error, IncomingDecodeError)


class DNSIncoming(DNSMessage, QuietLogger):

    """Object representation of an incoming DNS packet"""

    __slots__ = (
        'offset',
        'data',
        'data_len',
        'name_cache',
        'questions',
        '_answers',
        'id',
        'num_questions',
        'num_answers',
        'num_authorities',
        'num_additionals',
        'valid',
        'now',
        'scope_id',
        'source',
    )

    def __init__(
        self,
        data: bytes,
        source: Optional[Tuple[str, int]] = None,
        scope_id: Optional[int] = None,
        now: Optional[float] = None,
    ) -> None:
        """Constructor from string holding bytes of packet"""
        super().__init__(0)
        self.offset = 0
        self.data = data
        self.data_len = len(data)
        self.name_cache: Dict[int, List[str]] = {}
        self.questions: List[DNSQuestion] = []
        self._answers: List[DNSRecord] = []
        self.id = 0
        self.num_questions = 0
        self.num_answers = 0
        self.num_authorities = 0
        self.num_additionals = 0
        self.valid = False
        self._read_others = False
        self.now = now or current_time_millis()
        self.source = source
        self.scope_id = scope_id
        self._parse_data(self._initial_parse)

    def _initial_parse(self) -> None:
        """Parse the data needed to initalize the packet object."""
        self.read_header()
        self.read_questions()
        if not self.num_questions:
            self.read_others()
        self.valid = True

    def _parse_data(self, parser_call: Callable) -> None:
        """Parse part of the packet and catch exceptions."""
        try:
            parser_call()
        except DECODE_EXCEPTIONS:
            self.log_exception_debug(
                'Received invalid packet from %s at offset %d while unpacking %r',
                self.source,
                self.offset,
                self.data,
            )

    @property
    def answers(self) -> List[DNSRecord]:
        """Answers in the packet."""
        if not self._read_others:
            self._parse_data(self.read_others)
        return self._answers

    def __repr__(self) -> str:
        return '<DNSIncoming:{%s}>' % ', '.join(
            [
                'id=%s' % self.id,
                'flags=%s' % self.flags,
                'truncated=%s' % self.truncated,
                'n_q=%s' % self.num_questions,
                'n_ans=%s' % self.num_answers,
                'n_auth=%s' % self.num_authorities,
                'n_add=%s' % self.num_additionals,
                'questions=%s' % self.questions,
                'answers=%s' % self.answers,
            ]
        )

    def unpack(self, format_: bytes, length: int) -> tuple:
        self.offset += length
        return struct.unpack(format_, self.data[self.offset - length : self.offset])

    def read_header(self) -> None:
        """Reads header portion of packet"""
        (
            self.id,
            self.flags,
            self.num_questions,
            self.num_answers,
            self.num_authorities,
            self.num_additionals,
        ) = self.unpack(b'!6H', 12)

    def read_questions(self) -> None:
        """Reads questions section of packet"""
        self.questions = [
            DNSQuestion(self.read_name(), *self.unpack(b'!HH', 4)) for _ in range(self.num_questions)
        ]

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
        return cast(int, self.unpack(b'!H', 2)[0])

    def read_others(self) -> None:
        """Reads the answers, authorities and additionals section of the
        packet"""
        self._read_others = True
        n = self.num_answers + self.num_authorities + self.num_additionals
        for _ in range(n):
            domain = self.read_name()
            type_, class_, ttl, length = self.unpack(b'!HHiH', 10)
            end = self.offset + length
            rec = None
            try:
                rec = self.read_record(domain, type_, class_, ttl, length)
            except DECODE_EXCEPTIONS:
                # Skip records that fail to decode if we know the length
                # If the packet is really corrupt read_name and the unpack
                # above would fail and hit the exception catch in read_others
                self.offset = end
                log.debug(
                    'Unable to parse; skipping record for %s with type %s at offset %d while unpacking %r',
                    domain,
                    _TYPES.get(type_, type_),
                    self.offset,
                    self.data,
                    exc_info=True,
                )
            if rec is not None:
                self._answers.append(rec)

    def read_record(self, domain: str, type_: int, class_: int, ttl: int, length: int) -> Optional[DNSRecord]:
        """Read known records types and skip unknown ones."""
        if type_ == _TYPE_A:
            return DNSAddress(domain, type_, class_, ttl, self.read_string(4), created=self.now)
        if type_ in (_TYPE_CNAME, _TYPE_PTR):
            return DNSPointer(domain, type_, class_, ttl, self.read_name(), self.now)
        if type_ == _TYPE_TXT:
            return DNSText(domain, type_, class_, ttl, self.read_string(length), self.now)
        if type_ == _TYPE_SRV:
            return DNSService(
                domain,
                type_,
                class_,
                ttl,
                self.read_unsigned_short(),
                self.read_unsigned_short(),
                self.read_unsigned_short(),
                self.read_name(),
                self.now,
            )
        if type_ == _TYPE_HINFO:
            return DNSHinfo(
                domain,
                type_,
                class_,
                ttl,
                self.read_character_string().decode('utf-8'),
                self.read_character_string().decode('utf-8'),
                self.now,
            )
        if type_ == _TYPE_AAAA:
            return DNSAddress(
                domain, type_, class_, ttl, self.read_string(16), created=self.now, scope_id=self.scope_id
            )
        if type_ == _TYPE_NSEC:
            name_start = self.offset
            return DNSNsec(
                domain,
                type_,
                class_,
                ttl,
                self.read_name(),
                self.read_bitmap(name_start + length),
                self.now,
            )
        # Try to ignore types we don't know about
        # Skip the payload for the resource record so the next
        # records can be parsed correctly
        self.offset += length
        return None

    def read_bitmap(self, end: int) -> List[int]:
        """Reads an NSEC bitmap from the packet."""
        rdtypes = []
        while self.offset < end:
            window = self.data[self.offset]
            bitmap_length = self.data[self.offset + 1]
            for i, byte in enumerate(self.data[self.offset + 2 : self.offset + 2 + bitmap_length]):
                for bit in range(0, 8):
                    if byte & (0x80 >> bit):
                        rdtypes.append(bit + window * 256 + i * 8)
            self.offset += 2 + bitmap_length
        return rdtypes

    def read_name(self) -> str:
        """Reads a domain name from the packet."""
        labels: List[str] = []
        seen_pointers: Set[int] = set()
        self.offset = self._decode_labels_at_offset(self.offset, labels, seen_pointers)
        name = ".".join(labels) + "."
        if len(name) > MAX_NAME_LENGTH:
            raise IncomingDecodeError(
                f"DNS name {name} exceeds maximum length of {MAX_NAME_LENGTH} from {self.source}"
            )
        return name

    def _decode_labels_at_offset(self, off: int, labels: List[str], seen_pointers: Set[int]) -> int:
        # This is a tight loop that is called frequently, small optimizations can make a difference.
        while off < self.data_len:
            length = self.data[off]
            if length == 0:
                return off + DNS_COMPRESSION_HEADER_LEN

            if length < 0x40:
                label_idx = off + DNS_COMPRESSION_HEADER_LEN
                labels.append(self.data[label_idx : label_idx + length].decode('utf-8', 'replace'))
                off += DNS_COMPRESSION_HEADER_LEN + length
                continue

            if length < 0xC0:
                raise IncomingDecodeError(
                    f"DNS compression type {length} is unknown at {off} from {self.source}"
                )

            # We have a DNS compression pointer
            link = (length & 0x3F) * 256 + self.data[off + 1]
            if link > self.data_len:
                raise IncomingDecodeError(
                    f"DNS compression pointer at {off} points to {link} beyond packet from {self.source}"
                )
            if link == off:
                raise IncomingDecodeError(
                    f"DNS compression pointer at {off} points to itself from {self.source}"
                )
            if link in seen_pointers:
                raise IncomingDecodeError(
                    f"DNS compression pointer at {off} was seen again from {self.source}"
                )
            linked_labels = self.name_cache.get(link, [])
            if not linked_labels:
                seen_pointers.add(link)
                self._decode_labels_at_offset(link, linked_labels, seen_pointers)
                self.name_cache[link] = linked_labels
            labels.extend(linked_labels)
            if len(labels) > MAX_DNS_LABELS:
                raise IncomingDecodeError(
                    f"Maximum dns labels reached while processing pointer at {off} from {self.source}"
                )
            return off + DNS_COMPRESSION_POINTER_LEN

        raise IncomingDecodeError("Corrupt packet received while decoding name from {self.source}")
