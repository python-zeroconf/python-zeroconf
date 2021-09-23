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
import struct
from typing import Any, Dict, List, Optional, Sequence, Tuple, Union

from . import DNSMessage
from .incoming import DNSIncoming
from .._cache import DNSCache
from .._dns import DNSPointer, DNSQuestion, DNSRecord
from .._exceptions import NamePartTooLongException
from .._logger import log
from ..const import (
    _CLASS_UNIQUE,
    _DNS_PACKET_HEADER_LEN,
    _FLAGS_TC,
    _MAX_MSG_ABSOLUTE,
    _MAX_MSG_TYPICAL,
)


class DNSOutgoing(DNSMessage):

    """Object representation of an outgoing packet"""

    __slots__ = (
        'finished',
        'id',
        'multicast',
        'packets_data',
        'names',
        'data',
        'size',
        'allow_long',
        'state',
        'questions',
        'answers',
        'authorities',
        'additionals',
    )

    def __init__(self, flags: int, multicast: bool = True, id_: int = 0) -> None:
        super().__init__(flags)
        self.finished = False
        self.id = id_
        self.multicast = multicast
        self.packets_data: List[bytes] = []

        # these 3 are per-packet -- see also _reset_for_next_packet()
        self.names: Dict[str, int] = {}
        self.data: List[bytes] = []
        self.size: int = _DNS_PACKET_HEADER_LEN
        self.allow_long: bool = True

        self.state = self.State.init

        self.questions: List[DNSQuestion] = []
        self.answers: List[Tuple[DNSRecord, float]] = []
        self.authorities: List[DNSPointer] = []
        self.additionals: List[DNSRecord] = []

    def _reset_for_next_packet(self) -> None:
        self.names = {}
        self.data = []
        self.size = _DNS_PACKET_HEADER_LEN
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
        if record is not None and (now == 0 or not record.is_expired(now)):
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
        self, cache: DNSCache, now: float, name: str, type_: int, class_: int
    ) -> None:
        """Add a question if it is not already cached."""
        cached_entry = cache.get_by_details(name, type_, class_)
        if not cached_entry:
            self.add_question(DNSQuestion(name, type_, class_))
        else:
            self.add_answer_at_time(cached_entry, now)

    def add_question_or_all_cache(
        self, cache: DNSCache, now: float, name: str, type_: int, class_: int
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

    def _pack(self, format_: Union[bytes, str], size: int, value: Any) -> None:
        self.data.append(struct.pack(format_, value))
        self.size += size

    def _write_byte(self, value: int) -> None:
        """Writes a single byte to the packet"""
        self._pack(b'!c', 1, bytes((value,)))

    def _insert_short_at_start(self, value: int) -> None:
        """Inserts an unsigned short at the start of the packet"""
        self.data.insert(0, struct.pack(b'!H', value))

    def _replace_short(self, index: int, value: int) -> None:
        """Replaces an unsigned short in a certain position in the packet"""
        self.data[index] = struct.pack(b'!H', value)

    def write_short(self, value: int) -> None:
        """Writes an unsigned short to the packet"""
        self._pack(b'!H', 2, value)

    def _write_int(self, value: Union[float, int]) -> None:
        """Writes an unsigned integer to the packet"""
        self._pack(b'!I', 4, int(value))

    def write_string(self, value: bytes) -> None:
        """Writes a string to the packet"""
        assert isinstance(value, bytes)
        self.data.append(value)
        self.size += len(value)

    def _write_utf(self, s: str) -> None:
        """Writes a UTF-8 string of a given length to the packet"""
        utfstr = s.encode('utf-8')
        length = len(utfstr)
        if length > 64:
            raise NamePartTooLongException
        self._write_byte(length)
        self.write_string(utfstr)

    def write_character_string(self, value: bytes) -> None:
        assert isinstance(value, bytes)
        length = len(value)
        if length > 256:
            raise NamePartTooLongException
        self._write_byte(length)
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
        name_length = None
        if name.endswith('.'):
            name = name[: len(name) - 1]
        labels = name.split('.')
        # Write each new label or a pointer to the existing
        # on in the packet
        start_size = self.size
        for count in range(len(labels)):
            label = name if count == 0 else '.'.join(labels[count:])
            index = self.names.get(label)
            if index:
                # If part of the name already exists in the packet,
                # create a pointer to it
                self._write_byte((index >> 8) | 0xC0)
                self._write_byte(index & 0xFF)
                return
            if name_length is None:
                name_length = len(name.encode('utf-8'))
            self.names[label] = start_size + name_length - len(label.encode('utf-8'))
            self._write_utf(labels[count])

        # this is the end of a name
        self._write_byte(0)

    def _write_question(self, question: DNSQuestion) -> bool:
        """Writes a question to the packet"""
        start_data_length, start_size = len(self.data), self.size
        self.write_name(question.name)
        self.write_short(question.type)
        self._write_record_class(question)
        return self._check_data_limit_or_rollback(start_data_length, start_size)

    def _write_record_class(self, record: Union[DNSQuestion, DNSRecord]) -> None:
        """Write out the record class including the unique/unicast (QU) bit."""
        if record.unique and self.multicast:
            self.write_short(record.class_ | _CLASS_UNIQUE)
        else:
            self.write_short(record.class_)

    def _write_ttl(self, record: DNSRecord, now: float) -> None:
        """Write out the record ttl."""
        self._write_int(record.ttl if now == 0 else record.get_remaining_ttl(now))

    def _write_record(self, record: DNSRecord, now: float) -> bool:
        """Writes a record (answer, authoritative answer, additional) to
        the packet.  Returns True on success, or False if we did not
        because the packet because the record does not fit."""
        start_data_length, start_size = len(self.data), self.size
        self.write_name(record.name)
        self.write_short(record.type)
        self._write_record_class(record)
        self._write_ttl(record, now)
        index = len(self.data)
        self.write_short(0)  # Will get replaced with the actual size
        record.write(self)
        # Adjust size for the short we will write before this record
        length = sum(len(d) for d in self.data[index + 1 :])
        # Here we replace the 0 length short we wrote
        # before with the actual length
        self._replace_short(index, length)
        return self._check_data_limit_or_rollback(start_data_length, start_size)

    def _check_data_limit_or_rollback(self, start_data_length: int, start_size: int) -> bool:
        """Check data limit, if we go over, then rollback and return False."""
        len_limit = _MAX_MSG_ABSOLUTE if self.allow_long else _MAX_MSG_TYPICAL
        self.allow_long = False

        if self.size <= len_limit:
            return True

        log.debug("Reached data limit (size=%d) > (limit=%d) - rolling back", self.size, len_limit)
        del self.data[start_data_length:]
        self.size = start_size

        rollback_names = [name for name, idx in self.names.items() if idx >= start_size]
        for name in rollback_names:
            del self.names[name]
        return False

    def _write_questions_from_offset(self, questions_offset: int) -> int:
        questions_written = 0
        for question in self.questions[questions_offset:]:
            if not self._write_question(question):
                break
            questions_written += 1
        return questions_written

    def _write_answers_from_offset(self, answer_offset: int) -> int:
        answers_written = 0
        for answer, time_ in self.answers[answer_offset:]:
            if not self._write_record(answer, time_):
                break
            answers_written += 1
        return answers_written

    def _write_records_from_offset(self, records: Sequence[DNSRecord], offset: int) -> int:
        records_written = 0
        for record in records[offset:]:
            if not self._write_record(record, 0):
                break
            records_written += 1
        return records_written

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
            authorities_written = self._write_records_from_offset(self.authorities, authority_offset)
            additionals_written = self._write_records_from_offset(self.additionals, additional_offset)

            self._insert_short_at_start(additionals_written)
            self._insert_short_at_start(authorities_written)
            self._insert_short_at_start(answers_written)
            self._insert_short_at_start(questions_written)

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
                self._insert_short_at_start(self.flags | _FLAGS_TC)
            else:
                self._insert_short_at_start(self.flags)

            if self.multicast:
                self._insert_short_at_start(0)
            else:
                self._insert_short_at_start(self.id)

            self.packets_data.append(b''.join(self.data))
            self._reset_for_next_packet()

            if (questions_written + answers_written + authorities_written + additionals_written) == 0 and (
                len(self.questions) + len(self.answers) + len(self.authorities) + len(self.additionals)
            ) > 0:
                log.warning("packets() made no progress adding records; returning")
                break
        self.state = self.State.finished
        return self.packets_data
