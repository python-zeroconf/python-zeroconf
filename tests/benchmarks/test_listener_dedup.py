"""Benchmarks for the listener duplicate-packet suppression hot path.

These pin the cost of ``AsyncListener._process_datagram_at_time`` under
three packet-stream shapes that exercise the dedup branch differently:

- ``test_dedup_hit_same_payload`` — N copies of one payload (steady-state
  dedup hit).
- ``test_alternating_payloads`` — A, B, A, B, ... The single-slot
  remembered-last-packet dedup misses on every packet because each one
  differs from its immediate predecessor; a bounded recency window
  dedups after the second packet. This is the flood shape from
  issue #1724.
- ``test_unique_payloads`` — N distinct payloads (no dedup hit possible
  on either implementation). Measures the store/evict overhead on the
  miss path.

Downstream work is held constant across implementations by overriding
``handle_query_or_defer`` on a subclass with a no-op, so the only
remaining variable is the dedup decision itself.
"""

from __future__ import annotations

import pytest
from pytest_codspeed import BenchmarkFixture

from zeroconf import DNSOutgoing, DNSQuestion, const
from zeroconf._listener import AsyncListener
from zeroconf._utils.time import current_time_millis
from zeroconf.asyncio import AsyncZeroconf


class _InertListener(AsyncListener):
    """AsyncListener that skips response generation.

    The dedup branch is the only piece that diverges between the
    single-slot and bounded-window implementations. Stubbing query
    handling keeps the per-packet cost outside the dedup branch
    constant so the benchmark isolates the change under test.
    """

    def handle_query_or_defer(self, *args: object, **kwargs: object) -> None:  # type: ignore[override]
        return None


def _make_query_packet(name: str) -> bytes:
    out = DNSOutgoing(const._FLAGS_QR_QUERY, multicast=True)
    out.add_question(DNSQuestion(name, const._TYPE_PTR, const._CLASS_IN))
    return out.packets()[0]


_ITERATIONS = 200
_ADDRS: tuple[str, int] = ("192.0.2.1", 5353)


def _build_listener(aiozc: AsyncZeroconf) -> _InertListener:
    zc = aiozc.zeroconf
    # A non-empty registry keeps the realistic code path live (the early
    # ``has_entries`` exit would otherwise bypass the per-packet work we
    # want to measure). Toggling the flag directly avoids the event-loop
    # round-trip that ``async_register_service`` would impose.
    zc.registry.has_entries = True
    listener = _InertListener(zc)
    listener.transport = object()  # type: ignore[assignment]
    return listener


@pytest.mark.asyncio
async def test_dedup_hit_same_payload(benchmark: BenchmarkFixture) -> None:
    """Steady-state dedup hit: same payload repeated."""
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    await aiozc.zeroconf.async_wait_for_start()
    listener = _build_listener(aiozc)
    packet = _make_query_packet("a._http._tcp.local.")
    data_len = len(packet)
    # Prime the dedup state so the first iteration is already a hit.
    listener._process_datagram_at_time(False, data_len, current_time_millis(), packet, _ADDRS)

    @benchmark
    def _run() -> None:
        # Single fresh timestamp keeps every call inside the
        # suppression interval so each one is a dedup hit.
        t = current_time_millis()
        for _ in range(_ITERATIONS):
            listener._process_datagram_at_time(False, data_len, t, packet, _ADDRS)

    await aiozc.async_close()


@pytest.mark.asyncio
async def test_alternating_payloads(benchmark: BenchmarkFixture) -> None:
    """Flood shape from issue #1724: A, B, A, B, ..."""
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    await aiozc.zeroconf.async_wait_for_start()
    listener = _build_listener(aiozc)
    packet_a = _make_query_packet("a._http._tcp.local.")
    packet_b = _make_query_packet("b._http._tcp.local.")
    len_a = len(packet_a)
    len_b = len(packet_b)

    @benchmark
    def _run() -> None:
        t = current_time_millis()
        for i in range(_ITERATIONS):
            if i & 1:
                listener._process_datagram_at_time(False, len_b, t, packet_b, _ADDRS)
            else:
                listener._process_datagram_at_time(False, len_a, t, packet_a, _ADDRS)

    await aiozc.async_close()


@pytest.mark.asyncio
async def test_unique_payloads(benchmark: BenchmarkFixture) -> None:
    """Stream of distinct payloads — no dedup hit on either implementation."""
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    await aiozc.zeroconf.async_wait_for_start()
    listener = _build_listener(aiozc)
    packets = [_make_query_packet(f"x{i}._http._tcp.local.") for i in range(_ITERATIONS)]
    lengths = [len(p) for p in packets]

    @benchmark
    def _run() -> None:
        t = current_time_millis()
        for packet, data_len in zip(packets, lengths, strict=True):
            listener._process_datagram_at_time(False, data_len, t, packet, _ADDRS)

    await aiozc.async_close()
