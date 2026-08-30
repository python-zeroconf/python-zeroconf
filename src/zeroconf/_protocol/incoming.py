"""A pure python implementation of multicast DNS service discovery.

Licensed under LGPL-2.1-or-later; see COPYING for details. This file is
part of a continuously modified work; modification dates are recorded
in the project's git history.
"""

from __future__ import annotations

import struct
import sys
from typing import Any

from .._dns import (
    DNSAddress,
    DNSHinfo,
    DNSNsec,
    DNSPointer,
    DNSQuestion,
    DNSRecord,
    DNSService,
    DNSText,
)
from .._exceptions import IncomingDecodeError
from .._logger import _mark_seen, log
from .._utils.time import current_time_millis
from ..const import (
    _FLAGS_QR_MASK,
    _FLAGS_QR_QUERY,
    _FLAGS_QR_RESPONSE,
    _FLAGS_TC,
    _TYPE_A,
    _TYPE_AAAA,
    _TYPE_CNAME,
    _TYPE_HINFO,
    _TYPE_NSEC,
    _TYPE_PTR,
    _TYPE_SRV,
    _TYPE_TXT,
    _TYPES,
)

DNS_COMPRESSION_HEADER_LEN = 1
DNS_COMPRESSION_POINTER_LEN = 2
MAX_DNS_LABELS = 128
MAX_NAME_LENGTH = 253
# DNS messages are hard-limited to 64 KiB; rejecting anything larger also
# keeps every unsigned `offset + length` comparison far from wrapping.
MAX_MSG_LEN = 0xFFFF

DECODE_EXCEPTIONS = (IndexError, struct.error, IncomingDecodeError, RecursionError)


_seen_logs: dict[str, None] = {}
_str = str
_int = int


class DNSIncoming:
    __slots__ = (
        "_answers",
        "_buf",
        "_data_len",
        "_did_read_others",
        "_has_qu_question",
        "_name_cache",
        "_name_str_cache",
        "_num_additionals",
        "_num_answers",
        "_num_authorities",
        "_num_questions",
        "_questions",
        "data",
        "flags",
        "id",
        "now",
        "offset",
        "scope_id",
        "source",
        "valid",
    )

    def __init__(
        self,
        data: bytes,
        source: tuple[str, int] | None = None,
        scope_id: int | None = None,
        now: float | None = None,
    ) -> None:
        self.data = data
        self.flags = 0
        self.id = 0
        self.now = now or current_time_millis()
        self.offset = 0
        self.scope_id = scope_id
        self.source = source
        self.valid = False

        self._answers: list[DNSRecord] = []
        # Borrowed pointer into `data`; every read and slice must be
        # preceded by an explicit bounds check against _data_len.
        self._buf = data
        self._data_len = len(data)
        self._did_read_others = False
        self._has_qu_question = False
        self._name_cache: dict[int, list[str]] = {}
        self._name_str_cache: dict[int, str] = {}
        self._num_additionals = 0
        self._num_answers = 0
        self._num_authorities = 0
        self._num_questions = 0
        self._questions: list[DNSQuestion] = []
        try:
            self._initial_parse()
        except DECODE_EXCEPTIONS:
            self._log_exception_debug(
                "Received invalid packet from %s at offset %d while unpacking %r",
                self.source,
                self.offset,
                self.data,
            )

    def __reduce__(self) -> tuple:
        # The compiled build holds a borrowed C pointer into `data` that
        # cannot survive pickling.
        raise TypeError(f"cannot pickle {type(self).__name__!r} object")

    def __repr__(self) -> str:
        return "<DNSIncoming:{}>".format(
            ", ".join(
                [
                    f"id={self.id}",
                    f"flags={self.flags}",
                    f"truncated={self.truncated}",
                    f"n_q={self._num_questions}",
                    f"n_ans={self._num_answers}",
                    f"n_auth={self._num_authorities}",
                    f"n_add={self._num_additionals}",
                    f"questions={self._questions}",
                    f"answers={self.answers()}",
                ]
            )
        )

    def answers(self) -> list[DNSRecord]:
        """Answers in the packet."""
        if not self._did_read_others:
            try:
                self._read_others()
            except DECODE_EXCEPTIONS:
                self._log_exception_debug(
                    "Received invalid packet from %s at offset %d while unpacking %r",
                    self.source,
                    self.offset,
                    self.data,
                )
        return self._answers

    def has_qu_question(self) -> bool:
        """True when at least one question requests a unicast response."""
        return self._has_qu_question

    def is_probe(self) -> bool:
        """True when the message carries authority records, marking a probe."""
        return self._num_authorities > 0

    def is_query(self) -> bool:
        """True when the QR flag marks the message as a query."""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_QUERY

    def is_response(self) -> bool:
        """True when the QR flag marks the message as a response."""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_RESPONSE

    @property
    def num_additionals(self) -> int:
        """Number of additionals in the packet."""
        return self._num_additionals

    @property
    def num_answers(self) -> int:
        """Number of answers in the packet."""
        return self._num_answers

    @property
    def num_authorities(self) -> int:
        """Number of authorities in the packet."""
        return self._num_authorities

    @property
    def num_questions(self) -> int:
        """Number of questions in the packet."""
        return self._num_questions

    @property
    def questions(self) -> list[DNSQuestion]:
        """Questions in the packet."""
        return self._questions

    @property
    def truncated(self) -> bool:
        """True when the TC bit is set."""
        return (self.flags & _FLAGS_TC) == _FLAGS_TC

    def _decode_labels_at_offset(
        self, off: _int, labels: list[_str], seen_pointers: set[_int] | None, depth: _int
    ) -> int:
        # This is a tight loop that is called frequently, small optimizations can make a difference.
        if depth > MAX_DNS_LABELS:
            raise IncomingDecodeError(
                f"DNS compression pointer chain exceeds {MAX_DNS_LABELS} at {off} from {self.source}"
            )
        buf = self._buf
        while off < self._data_len:
            length = buf[off]
            if length == 0:
                return off + DNS_COMPRESSION_HEADER_LEN

            if length < 0x40:
                label_idx = off + DNS_COMPRESSION_HEADER_LEN
                # Sliced from `data`, not `_buf`: a label running past the end
                # truncates here and the loop raises corrupt-packet below.
                labels.append(self.data[label_idx : label_idx + length].decode("utf-8", "replace"))
                off += DNS_COMPRESSION_HEADER_LEN + length
                continue

            if length < 0xC0:
                raise IncomingDecodeError(
                    f"DNS compression type {length} is unknown at {off} from {self.source}"
                )

            # We have a DNS compression pointer
            if off + 1 >= self._data_len:
                raise IncomingDecodeError(f"DNS compression pointer at {off} is truncated from {self.source}")
            link_data = buf[off + 1]
            link = (length & 0x3F) * 256 + link_data
            link_py_int = link
            if link >= self._data_len:
                raise IncomingDecodeError(
                    f"DNS compression pointer at {off} points to {link} beyond packet from {self.source}"
                )
            if link == off:
                raise IncomingDecodeError(
                    f"DNS compression pointer at {off} points to itself from {self.source}"
                )
            if seen_pointers is not None and link_py_int in seen_pointers:
                raise IncomingDecodeError(
                    f"DNS compression pointer at {off} was seen again from {self.source}"
                )
            linked_labels = self._name_cache.get(link_py_int)
            if not linked_labels:
                if seen_pointers is None:
                    # Deferred allocation: only names that follow an
                    # uncached pointer pay for loop detection.
                    seen_pointers = set()
                seen_pointers.add(link_py_int)
                linked_labels = []
                self._decode_labels_at_offset(link, linked_labels, seen_pointers, depth + 1)
                self._name_cache[link_py_int] = linked_labels
            labels.extend(linked_labels)
            if len(labels) > MAX_DNS_LABELS:
                raise IncomingDecodeError(
                    f"Maximum dns labels reached while processing pointer at {off} from {self.source}"
                )
            return off + DNS_COMPRESSION_POINTER_LEN

        raise IncomingDecodeError(f"Corrupt packet received while decoding name from {self.source}")

    def _initial_parse(self) -> None:
        """Parse the data needed to initialize the packet object."""
        if len(self.data) > MAX_MSG_LEN:
            raise IncomingDecodeError(
                f"Packet of {len(self.data)} bytes exceeds the {MAX_MSG_LEN} byte DNS limit "
                f"from {self.source}"
            )
        self._read_header()
        self._read_questions()
        if not self._num_questions:
            self._read_others()
        self.valid = True

    @classmethod
    def _log_exception_debug(cls, *logger_data: Any) -> None:
        log_exc_info = _mark_seen(_seen_logs, str(sys.exc_info()[1]))
        log.debug(*(logger_data or ["Exception occurred"]), exc_info=log_exc_info)

    def _read_bitmap(self, end: _int) -> list[int]:
        """Decode the NSEC type bitmap."""
        rdtypes = []
        if end > self._data_len:
            raise IncomingDecodeError(
                f"NSEC record end {end} overruns packet of {self._data_len} bytes from {self.source}"
            )
        buf = self._buf
        while self.offset < end:
            offset = self.offset
            offset_plus_one = offset + 1
            offset_plus_two = offset + 2
            # RFC 4034 §4.1.2: each window block is window-number byte +
            # bitmap-length byte (1..32) + bitmap. A bitmap_length that walks
            # past the record's declared end would otherwise leave self.offset
            # pointing inside (or past) the next record header, corrupting
            # every subsequent record in the same packet.
            if offset_plus_two > end:
                raise IncomingDecodeError(
                    f"NSEC bitmap window header truncated at offset {offset} from {self.source}"
                )
            bitmap_length = buf[offset_plus_one]
            bitmap_end = offset_plus_two + bitmap_length
            if bitmap_length == 0 or bitmap_length > 32 or bitmap_end > end:
                raise IncomingDecodeError(
                    f"NSEC bitmap length {bitmap_length} invalid or overruns record end "
                    f"at offset {offset} from {self.source}"
                )
            window_base = buf[offset] * 256
            for i in range(bitmap_length):
                byte = buf[offset_plus_two + i]
                if byte == 0:
                    continue
                bit_base = window_base + i * 8
                for bit in range(8):
                    if byte & (0x80 >> bit):
                        rdtypes.append(bit_base + bit)
            self.offset = bitmap_end
        return rdtypes

    def _read_character_string(self) -> str:
        """Decode a length prefixed character string."""
        if self.offset >= self._data_len:
            raise IncomingDecodeError(
                f"Character string at offset {self.offset} overruns packet of "
                f"{self._data_len} bytes from {self.source}"
            )
        length = self._buf[self.offset]
        start = self.offset + 1
        end = start + length
        # Python slicing silently truncates when indices exceed the buffer,
        # but self.offset still advances by the declared length below; without
        # this check a record with an inflated character-string length would
        # land in the cache carrying a payload shorter than the wire claimed
        # and leave the parser pointed past _data_len for the next record.
        if end > self._data_len:
            raise IncomingDecodeError(
                f"Character string length {length} at offset {start} overruns "
                f"packet of {self._data_len} bytes from {self.source}"
            )
        info = self._buf[start:end].decode("utf-8", "replace")
        self.offset = end
        return info

    def _read_header(self) -> None:
        """Unpack the fixed twelve byte message header."""
        offset = self.offset
        if offset + 12 > self._data_len:
            raise IncomingDecodeError(
                f"DNS header at offset {offset} overruns packet of {self._data_len} bytes from {self.source}"
            )
        buf = self._buf
        self.offset += 12
        # The header has 6 unsigned shorts in network order
        self.id = buf[offset] << 8 | buf[offset + 1]
        self.flags = buf[offset + 2] << 8 | buf[offset + 3]
        self._num_questions = buf[offset + 4] << 8 | buf[offset + 5]
        self._num_answers = buf[offset + 6] << 8 | buf[offset + 7]
        self._num_authorities = buf[offset + 8] << 8 | buf[offset + 9]
        self._num_additionals = buf[offset + 10] << 8 | buf[offset + 11]

    def _read_name(self) -> str:
        """Decode a possibly compressed domain name at the current offset."""
        original_offset = self.offset
        name_str_cache = self._name_str_cache
        is_pure_pointer = False
        link = 0
        # A cache hit needs no re-validation because entries are only
        # written after a decode passed every check (bounds, loops, depth,
        # name length), and only at offsets inside the packet, so an
        # out-of-range link can only miss.
        if original_offset + DNS_COMPRESSION_POINTER_LEN <= self._data_len:
            length = self._buf[original_offset]
            if length >= 0xC0:
                is_pure_pointer = True
                link = (length & 0x3F) * 256 + self._buf[original_offset + 1]
                cached_name = name_str_cache.get(link)
                if cached_name is not None:
                    self.offset = original_offset + DNS_COMPRESSION_POINTER_LEN
                    return cached_name
        labels: list[str] = []
        self.offset = self._decode_labels_at_offset(original_offset, labels, None, 0)
        self._name_cache[original_offset] = labels
        name = ".".join(labels) + "."
        if len(name) > MAX_NAME_LENGTH:
            raise IncomingDecodeError(
                f"DNS name {name} exceeds maximum length of {MAX_NAME_LENGTH} from {self.source}"
            )
        name_str_cache[original_offset] = name
        if is_pure_pointer:
            # The whole name was one pointer, so the finished string is
            # also the name that starts at the pointer target.
            name_str_cache[link] = name
        return name

    def _read_others(self) -> None:
        """Parse everything after the question section in one pass."""
        self._did_read_others = True
        buf = self._buf
        answers = self._answers
        n = self._num_answers + self._num_authorities + self._num_additionals
        for _ in range(n):
            domain = self._read_name()
            offset = self.offset
            if offset + 10 > self._data_len:
                raise IncomingDecodeError(
                    f"Record header at offset {offset} overruns packet of "
                    f"{self._data_len} bytes from {self.source}"
                )
            self.offset += 10
            # type_, class_ and length are unsigned shorts in network order
            # ttl is an unsigned long in network order https://www.rfc-editor.org/errata/eid2130
            type_ = buf[offset] << 8 | buf[offset + 1]
            class_ = buf[offset + 2] << 8 | buf[offset + 3]
            ttl = buf[offset + 4] << 24 | buf[offset + 5] << 16 | buf[offset + 6] << 8 | buf[offset + 7]
            length = buf[offset + 8] << 8 | buf[offset + 9]
            end = self.offset + length
            rec = None
            try:
                rec = self._read_record(domain, type_, class_, ttl, length)
            except DECODE_EXCEPTIONS:
                # Skip records that fail to decode if we know the length
                # If the packet is really corrupt read_name and the unpack
                # above would fail and hit the exception catch in read_others
                self.offset = end
                log.debug(
                    "Unable to parse; skipping record for %s with type %s at offset %d while unpacking %r",
                    domain,
                    _TYPES.get(type_, type_),
                    self.offset,
                    self.data,
                    exc_info=True,
                )
            if rec is not None and self.offset != end:
                # The decoded record consumed a different number of bytes than
                # rdlength advertised. The record is built from a slice that
                # straddles its rdata boundary, so drop it and resync to the
                # declared end so the next record header lands aligned.
                log.debug(
                    "Record for %s with type %s did not consume exactly rdlength=%d; dropping",
                    domain,
                    _TYPES.get(type_, type_),
                    length,
                )
                self.offset = end
                rec = None
            if rec is not None:
                answers.append(rec)

    def _read_questions(self) -> None:
        """Parse the question entries."""
        buf = self._buf
        questions = self._questions
        for _ in range(self._num_questions):
            name = self._read_name()
            offset = self.offset
            if offset + 4 > self._data_len:
                raise IncomingDecodeError(
                    f"Question at offset {offset} overruns packet of "
                    f"{self._data_len} bytes from {self.source}"
                )
            self.offset += 4
            # The question has 2 unsigned shorts in network order
            type_ = buf[offset] << 8 | buf[offset + 1]
            class_ = buf[offset + 2] << 8 | buf[offset + 3]
            question = DNSQuestion.__new__(DNSQuestion)
            question._fast_init(name, type_, class_)
            if question.unique:  # QU questions use the same bit as unique
                self._has_qu_question = True
            questions.append(question)

    def _read_record(
        self, domain: _str, type_: _int, class_: _int, ttl: _int, length: _int
    ) -> DNSRecord | None:
        """Read known records types and skip unknown ones."""
        if type_ == _TYPE_A:
            address_rec = DNSAddress.__new__(DNSAddress)
            address_rec._fast_init(domain, type_, class_, ttl, self._read_string(4), None, self.now)
            return address_rec
        if type_ in (_TYPE_CNAME, _TYPE_PTR):
            pointer_rec = DNSPointer.__new__(DNSPointer)
            pointer_rec._fast_init(domain, type_, class_, ttl, self._read_name(), self.now)
            return pointer_rec
        if type_ == _TYPE_TXT:
            text_rec = DNSText.__new__(DNSText)
            text_rec._fast_init(domain, type_, class_, ttl, self._read_string(length), self.now)
            return text_rec
        if type_ == _TYPE_SRV:
            offset = self.offset
            if offset + 6 > self._data_len:
                raise IncomingDecodeError(
                    f"SRV record at offset {offset} overruns packet of "
                    f"{self._data_len} bytes from {self.source}"
                )
            buf = self._buf
            self.offset += 6
            # The SRV record has 3 unsigned shorts in network order
            priority = buf[offset] << 8 | buf[offset + 1]
            weight = buf[offset + 2] << 8 | buf[offset + 3]
            port = buf[offset + 4] << 8 | buf[offset + 5]
            srv_rec = DNSService.__new__(DNSService)
            srv_rec._fast_init(
                domain,
                type_,
                class_,
                ttl,
                priority,
                weight,
                port,
                self._read_name(),
                self.now,
            )
            return srv_rec
        if type_ == _TYPE_HINFO:
            hinfo_rec = DNSHinfo.__new__(DNSHinfo)
            hinfo_rec._fast_init(
                domain,
                type_,
                class_,
                ttl,
                self._read_character_string(),
                self._read_character_string(),
                self.now,
            )
            return hinfo_rec
        if type_ == _TYPE_AAAA:
            address_rec = DNSAddress.__new__(DNSAddress)
            address_rec._fast_init(
                domain,
                type_,
                class_,
                ttl,
                self._read_string(16),
                self.scope_id,
                self.now,
            )
            return address_rec
        if type_ == _TYPE_NSEC:
            name_start = self.offset
            nsec_rec = DNSNsec.__new__(DNSNsec)
            nsec_rec._fast_init(
                domain,
                type_,
                class_,
                ttl,
                self._read_name(),
                self._read_bitmap(name_start + length),
                self.now,
            )
            return nsec_rec
        self.offset += length
        return None

    def _read_string(self, length: _int) -> bytes:
        """Slice the next length bytes out of the buffer."""
        start = self.offset
        end = start + length
        if end > self._data_len:
            raise IncomingDecodeError(
                f"String length {length} at offset {start} overruns "
                f"packet of {self._data_len} bytes from {self.source}"
            )
        info = self._buf[start:end]
        self.offset = end
        return info
