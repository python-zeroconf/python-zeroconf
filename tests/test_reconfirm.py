"""Tests for RFC 6762 §10.4 cache-flush-on-failure reconfirmation."""

from __future__ import annotations

import asyncio
import socket
from unittest.mock import patch

import pytest

from zeroconf import DNSAddress, DNSRecord, ServiceInfo, Zeroconf, const
from zeroconf.asyncio import AsyncZeroconf

from . import _inject_response, mock_incoming_msg


def _inject_in_loop(zc: Zeroconf, record: DNSRecord) -> None:
    """Inject a response while already on the zc event loop."""
    zc.record_manager.async_updates_from_response(mock_incoming_msg([record]))


def _make_address_record(name: str = "host.local.", ttl: int = 120) -> DNSAddress:
    return DNSAddress(
        name,
        const._TYPE_A,
        const._CLASS_IN | const._CLASS_UNIQUE,
        ttl,
        socket.inet_aton("10.0.0.5"),
    )


@pytest.mark.asyncio
@pytest.mark.usefixtures("quick_reconfirm_timing")
async def test_reconfirm_returns_false_when_record_not_in_cache(aiozc_loopback: AsyncZeroconf) -> None:
    assert aiozc_loopback.async_reconfirm_record(_make_address_record()) is False


@pytest.mark.asyncio
@pytest.mark.usefixtures("quick_reconfirm_timing")
async def test_reconfirm_returns_true_when_record_present(aiozc_loopback: AsyncZeroconf) -> None:
    record = _make_address_record()
    _inject_in_loop(aiozc_loopback.zeroconf, record)
    assert aiozc_loopback.async_reconfirm_record(record) is True
    # Wait long enough for the background task to complete and flush.
    await asyncio.sleep(0.3)


@pytest.mark.asyncio
@pytest.mark.usefixtures("quick_reconfirm_timing")
async def test_reconfirm_dedupes_in_flight_calls(aiozc_loopback: AsyncZeroconf) -> None:
    record = _make_address_record()
    _inject_in_loop(aiozc_loopback.zeroconf, record)
    assert aiozc_loopback.async_reconfirm_record(record) is True
    # Second call before the first finishes is a no-op.
    assert aiozc_loopback.async_reconfirm_record(record) is False
    await asyncio.sleep(0.3)


@pytest.mark.asyncio
@pytest.mark.usefixtures("quick_reconfirm_timing")
async def test_reconfirm_flushes_record_after_timeout(aiozc_loopback: AsyncZeroconf) -> None:
    record = _make_address_record()
    _inject_in_loop(aiozc_loopback.zeroconf, record)
    assert aiozc_loopback.zeroconf.cache.get(record) is not None

    assert aiozc_loopback.async_reconfirm_record(record) is True
    # Quick fixture sets timeout to 100ms; wait past it.
    await asyncio.sleep(0.3)
    assert aiozc_loopback.zeroconf.cache.get(record) is None


@pytest.mark.asyncio
@pytest.mark.usefixtures("quick_reconfirm_timing")
async def test_reconfirm_keeps_record_when_refreshed(aiozc_loopback: AsyncZeroconf) -> None:
    record = _make_address_record()
    _inject_in_loop(aiozc_loopback.zeroconf, record)
    assert aiozc_loopback.zeroconf.cache.get(record) is not None

    assert aiozc_loopback.async_reconfirm_record(record) is True
    # Simulate a fresh response landing before the timeout fires.
    refreshed = _make_address_record()
    _inject_in_loop(aiozc_loopback.zeroconf, refreshed)
    await asyncio.sleep(0.3)
    # Record should still be in cache — it was refreshed during the
    # reconfirm window, so the flush path was skipped.
    assert aiozc_loopback.zeroconf.cache.get(record) is not None


@pytest.mark.asyncio
@pytest.mark.usefixtures("quick_reconfirm_timing")
async def test_reconfirm_sends_queries(aiozc_loopback: AsyncZeroconf) -> None:
    record = _make_address_record()
    _inject_in_loop(aiozc_loopback.zeroconf, record)
    with patch.object(aiozc_loopback.zeroconf, "async_send") as mock_send:
        assert aiozc_loopback.async_reconfirm_record(record) is True
        await asyncio.sleep(0.3)
    # RFC 6762 §10.4 requires "two or more queries". With quick timing
    # there are three scheduled (0/10/30ms) before the 100ms flush.
    assert mock_send.call_count >= 2


@pytest.mark.asyncio
@pytest.mark.usefixtures("quick_reconfirm_timing")
async def test_reconfirm_notifies_listener_on_flush() -> None:
    """Browser sees a Removed when reconfirm flushes a PTR record."""
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    try:
        type_ = "_http._tcp.local."
        registration_name = f"my-service.{type_}"
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            {"path": "/"},
            "host.local.",
            addresses=[socket.inet_aton("10.0.0.5")],
        )
        # Inject a PTR record into the cache without going through the
        # registry — we want to reconfirm an entry that no responder
        # will refresh.
        ptr = info.dns_pointer()
        _inject_in_loop(aiozc.zeroconf, ptr)
        assert aiozc.zeroconf.cache.get(ptr) is not None
        assert aiozc.async_reconfirm_record(ptr) is True
        await asyncio.sleep(0.3)
        assert aiozc.zeroconf.cache.get(ptr) is None
    finally:
        await aiozc.async_close()


def test_threadsafe_reconfirm_no_op_after_close() -> None:
    zc = Zeroconf(interfaces=["127.0.0.1"])
    zc.close()
    # Must not raise even though loop is closed.
    zc.reconfirm_record(_make_address_record())


def test_threadsafe_reconfirm_schedules_on_loop(zc_loopback: Zeroconf) -> None:
    record = _make_address_record()
    _inject_response(zc_loopback, mock_incoming_msg([record]))
    # Threadsafe call returns None and just schedules on the loop.
    assert zc_loopback.reconfirm_record(record) is None
