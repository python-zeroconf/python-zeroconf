"""Fuzz tests for DNSIncoming.

The constructor contract: parsing any byte sequence must never raise; a
packet that fails to decode sets ``valid = False`` instead.
"""

from __future__ import annotations

import socket

from hypothesis import given
from hypothesis import strategies as st

from zeroconf import DNSIncoming, DNSNsec, DNSOutgoing, const
from zeroconf._dns import DNSRecord

from .benchmarks.test_incoming import generate_packets

# Slack past the codec's cap so the fuzzer also probes oversized input
MAX_PACKET_SIZE = const._MAX_MSG_ABSOLUTE + 256


def _nsec_packet() -> bytes:
    out = DNSOutgoing(const._FLAGS_QR_RESPONSE | const._FLAGS_AA)
    out.add_answer_at_time(
        DNSNsec(
            "fuzz._hap._tcp.local.",
            const._TYPE_NSEC,
            const._CLASS_IN | const._CLASS_UNIQUE,
            const._DNS_OTHER_TTL,
            "fuzz._hap._tcp.local.",
            [const._TYPE_TXT, const._TYPE_SRV],
        ),
        0,
    )
    return out.packets()[0]


CORPUS = [*generate_packets(), _nsec_packet()]


def _parse(data: bytes) -> list[DNSRecord]:
    """Parse and touch every public surface; any exception is a bug."""
    incoming = DNSIncoming(data)
    assert isinstance(incoming.valid, bool)
    incoming.is_query()
    incoming.is_response()
    incoming.has_qu_question()
    assert incoming.questions is not None
    answers = incoming.answers()
    assert isinstance(answers, list)
    for record in answers:
        repr(record)
        hash(record)
    return answers


def test_corpus_parses_cleanly() -> None:
    """Positive control: the fuzz corpus itself must parse fully."""
    for packet in CORPUS:
        incoming = DNSIncoming(packet)
        assert incoming.valid
        assert incoming.answers()


@given(data=st.binary(max_size=MAX_PACKET_SIZE))
def test_arbitrary_bytes_never_raise(data: bytes) -> None:
    """Random garbage must parse or fail quietly, and parsing is deterministic."""
    answers = _parse(data)
    assert _parse(data) == answers


@given(
    packet=st.sampled_from(CORPUS),
    mutations=st.lists(
        st.tuples(st.integers(min_value=0, max_value=MAX_PACKET_SIZE), st.integers(0, 255)),
        min_size=1,
        max_size=8,
    ),
)
def test_mutated_valid_packets_never_raise(packet: bytes, mutations: list[tuple[int, int]]) -> None:
    """Valid packets with flipped bytes must never raise."""
    data = bytearray(packet)
    for pos, value in mutations:
        data[pos % len(data)] = value
    _parse(bytes(data))


@given(packet=st.sampled_from(CORPUS), keep=st.integers(min_value=0, max_value=MAX_PACKET_SIZE))
def test_truncated_packets_never_raise(packet: bytes, keep: int) -> None:
    """Truncation at any byte boundary must never raise."""
    _parse(packet[: keep % (len(packet) + 1)])


@given(
    packet=st.sampled_from(CORPUS),
    pos=st.integers(min_value=0, max_value=MAX_PACKET_SIZE),
    target=st.integers(min_value=0, max_value=0x3FFF),
)
def test_spliced_compression_pointers_never_raise(packet: bytes, pos: int, target: int) -> None:
    """Compression pointers injected anywhere, pointing anywhere, must never raise."""
    data = bytearray(packet)
    start = pos % (len(data) - 1)
    data[start] = 0xC0 | (target >> 8)
    data[start + 1] = target & 0xFF
    _parse(bytes(data))


@st.composite
def name_section_packets(draw: st.DrawFn) -> bytes:
    """A response header followed by an adversarial name built from labels and pointers."""
    tokens = draw(
        st.lists(
            st.one_of(
                st.binary(min_size=1, max_size=8).map(lambda label: bytes([len(label)]) + label),
                st.integers(min_value=0, max_value=0x3FFF).map(
                    lambda link: bytes([0xC0 | (link >> 8), link & 0xFF])
                ),
                st.just(b"\x00"),
            ),
            min_size=1,
            max_size=64,
        )
    )
    name = b"".join(tokens)
    header = b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    # type A, class IN, ttl 120, rdlength 4, addr
    tail = b"\x00\x01\x00\x01\x00\x00\x00\x78\x00\x04" + socket.inet_aton("127.0.0.1")
    return header + name + tail


@given(data=name_section_packets())
def test_adversarial_name_sections_never_raise(data: bytes) -> None:
    """Pointer chains, loops, self and forward pointers must never raise."""
    _parse(data)


@given(
    window=st.integers(min_value=0, max_value=255),
    bitmap_length=st.integers(min_value=0, max_value=255),
    bitmap=st.binary(max_size=40),
    rdlength=st.integers(min_value=0, max_value=64),
)
def test_nsec_bitmap_mutations_never_raise(
    window: int, bitmap_length: int, bitmap: bytes, rdlength: int
) -> None:
    """NSEC bitmaps with arbitrary window, length, and payload bytes must never raise."""
    name = b"\x04fuzz\x05local\x00"
    rdata = b"\xc0\x0c" + bytes([window, bitmap_length]) + bitmap
    header = b"\x00\x00\x84\x00\x00\x00\x00\x01\x00\x00\x00\x00"
    record = name + b"\x00\x2f\x00\x01\x00\x00\x00\x78" + bytes([rdlength >> 8, rdlength & 0xFF])
    _parse(header + record + rdata)


@given(
    tail_room=st.integers(min_value=0, max_value=32),
    rdlength=st.integers(min_value=0, max_value=0xFFFF),
    pointer_target=st.integers(min_value=0, max_value=0x3FFF),
)
def test_records_near_the_size_cap_never_raise(tail_room: int, rdlength: int, pointer_target: int) -> None:
    """Record headers and pointers in the last bytes below 64 KiB cannot wrap the guards."""
    tail_record = (
        b"\xc0\x0c"
        + b"\x00\x21\x00\x01\x00\x00\x00\x78"
        + bytes([rdlength >> 8, rdlength & 0xFF])
        + bytes(6)
        + bytes([0xC0 | (pointer_target >> 8), pointer_target & 0xFF])
    )
    total = 0xFFFF - tail_room
    skip_len = total - 12 - 11 - len(tail_record)
    # record 1 is an unknown type whose rdlength skips to the end region,
    # so record 2 is parsed with all offset arithmetic near the size cap
    packet = (
        b"\x00\x00\x84\x00\x00\x00\x00\x02\x00\x00\x00\x00"
        + b"\x00"
        + b"\x00\x00\x00\x01\x00\x00\x00\x00"
        + skip_len.to_bytes(2, "big")
        + bytes(skip_len)
        + tail_record
    )
    assert len(packet) == total
    _parse(packet)
