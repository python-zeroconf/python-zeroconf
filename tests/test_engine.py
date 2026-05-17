"""Unit tests for zeroconf._engine"""

from __future__ import annotations

import asyncio
import itertools
import logging
from unittest.mock import patch

import pytest

import zeroconf as r
from zeroconf import _engine, const
from zeroconf.asyncio import AsyncZeroconf

log = logging.getLogger("zeroconf")
original_logging_level = logging.NOTSET


def setup_module():
    global original_logging_level
    original_logging_level = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    if original_logging_level != logging.NOTSET:
        log.setLevel(original_logging_level)


# This test uses asyncio because it needs to access the cache directly
# which is not threadsafe
@pytest.mark.asyncio
async def test_reaper():
    with patch.object(_engine, "_CACHE_CLEANUP_INTERVAL", 0.01):
        aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
        zeroconf = aiozc.zeroconf
        cache = zeroconf.cache
        original_entries = list(itertools.chain(*(cache.entries_with_name(name) for name in cache.names())))
        record_with_10s_ttl = r.DNSAddress("a", const._TYPE_SOA, const._CLASS_IN, 10, b"a")
        record_with_1s_ttl = r.DNSAddress("a", const._TYPE_SOA, const._CLASS_IN, 1, b"b")
        # Backdate the short-lived record so it expires at the next
        # reaper tick instead of waiting the full TTL in real time.
        record_with_1s_ttl.created -= 2000
        zeroconf.cache.async_add_records([record_with_10s_ttl, record_with_1s_ttl])
        question = r.DNSQuestion("_hap._tcp._local.", const._TYPE_PTR, const._CLASS_IN)
        now = r.current_time_millis()
        # Add the question at `past` so the reaper's next tick will see
        # `current_time - past > _DUPLICATE_QUESTION_INTERVAL` and prune it,
        # while the initial `suppresses(now, ...)` check still sees the
        # question as recent (since `now - past == 999`, not strictly `> 999`).
        past = now - 999
        other_known_answers: set[r.DNSRecord] = {
            r.DNSPointer(
                "_hap._tcp.local.",
                const._TYPE_PTR,
                const._CLASS_IN,
                10000,
                "known-to-other._hap._tcp.local.",
            )
        }
        zeroconf.question_history.add_question_at_time(question, past, other_known_answers)
        assert zeroconf.question_history.suppresses(question, now, other_known_answers)
        entries_with_cache = list(itertools.chain(*(cache.entries_with_name(name) for name in cache.names())))
        await asyncio.sleep(0.1)
        entries = list(itertools.chain(*(cache.entries_with_name(name) for name in cache.names())))
        assert zeroconf.cache.get(record_with_1s_ttl) is None
        await aiozc.async_close()
        assert not zeroconf.question_history.suppresses(question, now, other_known_answers)
        assert entries != original_entries
        assert entries_with_cache != original_entries
        assert record_with_10s_ttl in entries
        assert record_with_1s_ttl not in entries


@pytest.mark.asyncio
async def test_setup_releases_socket_ownership() -> None:
    """Engine releases its pending-socket refs once each socket has a transport."""
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    try:
        await aiozc.zeroconf.async_wait_for_start()
        engine = aiozc.zeroconf.engine
        assert engine._listen_socket is None
        assert engine._respond_sockets == []
        assert engine.readers
        assert engine.senders
    finally:
        await aiozc.async_close()


@pytest.mark.asyncio
async def test_async_close_propagates_outer_cancellation() -> None:
    """Outer-task cancellation while awaiting setup propagates to the caller."""
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    try:
        await aiozc.zeroconf.async_wait_for_start()
        engine = aiozc.zeroconf.engine
        loop = asyncio.get_running_loop()
        original_task = engine._setup_task
        fake_task = loop.create_future()
        fake_task.set_exception(asyncio.CancelledError())
        engine._setup_task = fake_task  # type: ignore[assignment]
        try:
            with pytest.raises(asyncio.CancelledError):
                await engine._async_close()
        finally:
            engine._setup_task = original_task
    finally:
        await aiozc.async_close()


@pytest.mark.asyncio
async def test_reaper_aborts_when_done():
    """Ensure cache cleanup stops when zeroconf is done."""
    with patch.object(_engine, "_CACHE_CLEANUP_INTERVAL", 0.01):
        aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
        zeroconf = aiozc.zeroconf
        record_with_10s_ttl = r.DNSAddress("a", const._TYPE_SOA, const._CLASS_IN, 10, b"a")
        record_with_1s_ttl = r.DNSAddress("a", const._TYPE_SOA, const._CLASS_IN, 1, b"b")
        zeroconf.cache.async_add_records([record_with_10s_ttl, record_with_1s_ttl])
        assert zeroconf.cache.get(record_with_10s_ttl) is not None
        assert zeroconf.cache.get(record_with_1s_ttl) is not None
        await aiozc.async_close()
        # Backdate to immediate expiry so we don't have to wait the full
        # TTL; the assertion is that the reaper has stopped, so a
        # short sleep is enough to give it a chance to (incorrectly) run.
        record_with_1s_ttl.created -= 2000
        await asyncio.sleep(0.1)
        assert zeroconf.cache.get(record_with_10s_ttl) is not None
        assert zeroconf.cache.get(record_with_1s_ttl) is not None
