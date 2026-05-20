"""Multicast DNS Service Discovery for Python, v0.14-wmcbrine
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

from __future__ import annotations

import asyncio
import platform
import socket
import time
from collections.abc import Iterable
from functools import cache
from unittest import mock

import ifaddr

from zeroconf import DNSIncoming, DNSOutgoing, DNSQuestion, DNSRecord, Zeroconf, const
from zeroconf._history import QuestionHistory

_MONOTONIC_RESOLUTION = time.get_clock_info("monotonic").resolution

_IS_PYPY = platform.python_implementation() == "PyPy"

# get_service_info / async_request timeout for tests using the
# `quick_request_timing` fixture. The fixture cuts the initial-query
# delay to ~15ms (10ms _LISTENER_TIME + 1-5ms jitter), so 50ms is
# ample headroom for tests that only need to observe the first one
# or two queries.
QUICK_REQUEST_TIMEOUT_MS = 50

# Timeout for ZeroconfServiceTypes.find() / AsyncZeroconfServiceTypes.async_find()
# in loopback integration tests. `find()` is just `time.sleep(timeout)` —
# it doesn't short-circuit on the first matching response — so the
# timeout becomes a lower bound on the test runtime. Callers MUST use
# the `quick_timing` fixture, which shrinks the browser's first-query
# delay from RFC 6762 §5.2's 20-120ms window to 1-5ms; with that shave
# the registrar's response lands inside ~10ms and 75ms is ~7x headroom.
# PyPy's JIT is still warming up the first time this path runs early in
# the suite, so the round trip is too slow for 75ms; give it more room.
LOOPBACK_FIND_TIMEOUT = 0.3 if _IS_PYPY else 0.075

# IPv6-only `find()` on Linux GitHub runners can hit `[Errno 101] Network
# is unreachable` on the `::1` socket and falls back to the `fe80::` link-
# local interface, which adds latency the IPv4 loopback path never pays.
# PyPy widens that further with JIT warmup. The 75ms budget that works on
# IPv4 loopback is too tight for the V6Only path under those conditions
# — give it more headroom.
IPV6_LOOPBACK_FIND_TIMEOUT = 0.5


class QuestionHistoryWithoutSuppression(QuestionHistory):
    def suppresses(self, question: DNSQuestion, now: float, known_answers: set[DNSRecord]) -> bool:
        return False


def mock_incoming_msg(records: Iterable[DNSRecord]) -> DNSIncoming:
    """Build a `DNSIncoming` response message from a list of `DNSRecord`s."""
    generated = DNSOutgoing(const._FLAGS_QR_RESPONSE)
    for record in records:
        generated.add_answer_at_time(record, 0)
    return DNSIncoming(generated.packets()[0])


def _inject_responses(zc: Zeroconf, msgs: list[DNSIncoming]) -> None:
    """Inject a DNSIncoming response."""
    assert zc.loop is not None

    async def _wait_for_response():
        for msg in msgs:
            zc.record_manager.async_updates_from_response(msg)

    asyncio.run_coroutine_threadsafe(_wait_for_response(), zc.loop).result()


def _inject_response(zc: Zeroconf, msg: DNSIncoming) -> None:
    """Inject a DNSIncoming response."""
    _inject_responses(zc, [msg])


def _wait_for_start(zc: Zeroconf) -> None:
    """Wait for all sockets to be up and running."""
    assert zc.loop is not None
    asyncio.run_coroutine_threadsafe(zc.async_wait_for_start(), zc.loop).result()


@cache
def has_working_ipv6():
    """Return True if the system can bind an IPv6 address."""
    if not socket.has_ipv6:
        return False

    sock = None
    try:
        sock = socket.socket(socket.AF_INET6)
        sock.bind(("::1", 0))
    except Exception:
        return False
    finally:
        if sock:
            sock.close()

    for iface in ifaddr.get_adapters():
        for addr in iface.ips:
            if addr.is_IPv6 and iface.index is not None:
                return True
    return False


def _clear_cache(zc: Zeroconf) -> None:
    zc.cache.cache.clear()
    zc.question_history.clear()
    # Reset per-listener dedup state so identical packets sent in the
    # next phase of the test are not suppressed by the bounded recency
    # window populated during the previous phase.
    if zc.engine is not None:
        for protocol in zc.engine.protocols:
            protocol._recent_packets.clear()
            protocol.data = None
            protocol.last_time = 0


def _backdate_cache(zc: Zeroconf, ms: int = 1100) -> None:
    """Backdate every cached record's `created` time by `ms` milliseconds.

    rfc6762#section-10.2 keys off "received more than one second ago", so
    backdating is equivalent to sleeping `ms` in real time without the
    wall-clock wait.

    Iterate `store.values()`, not the dict directly — when a record is
    re-added with an equal hash, the key stays the original object while
    the value is replaced with the latest; mutating the key would update
    stale objects no one reads.
    """
    for store in zc.cache.cache.values():
        for record in store.values():
            record.created -= ms


def time_changed_millis(millis: float | None = None) -> None:
    """Call all scheduled events for a time."""
    loop = asyncio.get_running_loop()
    loop_time = loop.time()
    mock_seconds_into_future = millis / 1000 if millis is not None else loop_time

    with mock.patch("time.monotonic", return_value=mock_seconds_into_future):
        for task in list(loop._scheduled):  # type: ignore[attr-defined]
            if not isinstance(task, asyncio.TimerHandle):
                continue
            if task.cancelled():
                continue

            future_seconds = task.when() - (loop_time + _MONOTONIC_RESOLUTION)

            if mock_seconds_into_future >= future_seconds:
                task._run()
                task.cancel()
