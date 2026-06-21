"""Unit tests for the opt-in periodic interface-change monitor."""

from __future__ import annotations

import asyncio
from collections.abc import Callable
from unittest.mock import Mock, patch

import pytest

from zeroconf._utils import interface_monitor as im
from zeroconf._utils.interface_monitor import InterfaceMonitor
from zeroconf.asyncio import AsyncZeroconf


def _snapshot_cycler(snapshots: list[frozenset]) -> Callable[[], frozenset]:
    """Return the next snapshot each call, sticking on the last one."""
    it = iter(snapshots)

    def _next() -> frozenset:
        try:
            return next(it)
        except StopIteration:
            return snapshots[-1]

    return _next


def test_adapter_snapshot() -> None:
    adapter = Mock()
    adapter.index = 1
    ip = Mock()
    ip.ip = "192.168.1.5"
    adapter.ips = [ip]
    with patch.object(im.ifaddr, "get_adapters", return_value=[adapter]):
        assert im._adapter_snapshot() == frozenset({(1, "192.168.1.5")})


@pytest.mark.asyncio
async def test_monitor_rescans_on_change(aiozc_loopback: AsyncZeroconf) -> None:
    """A changed adapter snapshot triggers a rescan."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    updated = asyncio.Event()

    async def _fake_update() -> None:
        updated.set()

    with (
        patch.object(
            im, "_adapter_snapshot", side_effect=_snapshot_cycler([frozenset({"a"}), frozenset({"b"})])
        ),
        patch.object(zc, "async_update_interfaces", side_effect=_fake_update),
    ):
        await aiozc_loopback.async_start_interface_monitor(interval=0.001)
        await asyncio.wait_for(updated.wait(), timeout=1.0)
        await aiozc_loopback.async_stop_interface_monitor()


@pytest.mark.asyncio
async def test_monitor_no_rescan_when_unchanged(aiozc_loopback: AsyncZeroconf) -> None:
    """An unchanged snapshot does not trigger a rescan."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    with (
        patch.object(im, "_adapter_snapshot", return_value=frozenset({"same"})),
        patch.object(zc, "async_update_interfaces") as mock_update,
    ):
        await aiozc_loopback.async_start_interface_monitor(interval=0.001)
        await asyncio.sleep(0.02)
        await aiozc_loopback.async_stop_interface_monitor()
    mock_update.assert_not_called()


@pytest.mark.asyncio
async def test_monitor_survives_rescan_error(aiozc_loopback: AsyncZeroconf) -> None:
    """A failed rescan is logged and the monitor keeps running."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    calls = []

    async def _boom() -> None:
        calls.append(1)
        raise RuntimeError("boom")

    snapshots = [frozenset({"a"}), frozenset({"b"}), frozenset({"c"})]
    with (
        patch.object(im, "_adapter_snapshot", side_effect=_snapshot_cycler(snapshots)),
        patch.object(zc, "async_update_interfaces", side_effect=_boom),
    ):
        await aiozc_loopback.async_start_interface_monitor(interval=0.001)
        await asyncio.sleep(0.05)
        await aiozc_loopback.async_stop_interface_monitor()
    assert len(calls) >= 2


@pytest.mark.asyncio
async def test_start_interface_monitor_idempotent(aiozc_loopback: AsyncZeroconf) -> None:
    """Starting an already-running monitor is a no-op."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    with patch.object(im, "_adapter_snapshot", return_value=frozenset()):
        await aiozc_loopback.async_start_interface_monitor(interval=10)
        monitor = zc._interface_monitor
        assert monitor is not None
        task = monitor._task
        await aiozc_loopback.async_start_interface_monitor(interval=10)
        assert zc._interface_monitor is monitor
        assert monitor._task is task
        await aiozc_loopback.async_stop_interface_monitor()


@pytest.mark.asyncio
async def test_monitor_start_idempotent(aiozc_loopback: AsyncZeroconf) -> None:
    """InterfaceMonitor.start is a no-op when a task is already scheduled."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    with patch.object(im, "_adapter_snapshot", return_value=frozenset()):
        monitor = InterfaceMonitor(zc, interval=10)
    monitor.start()
    task = monitor._task
    monitor.start()
    assert monitor._task is task
    await monitor.async_stop()


@pytest.mark.asyncio
async def test_monitor_stop_without_start(aiozc_loopback: AsyncZeroconf) -> None:
    """Stopping a monitor that never started is a no-op."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    with patch.object(im, "_adapter_snapshot", return_value=frozenset()):
        monitor = InterfaceMonitor(zc)
    await monitor.async_stop()


@pytest.mark.asyncio
async def test_core_stop_interface_monitor_when_none(aiozc_loopback: AsyncZeroconf) -> None:
    """Stopping the monitor when none is running is a no-op."""
    await aiozc_loopback.zeroconf.async_wait_for_start()
    await aiozc_loopback.async_stop_interface_monitor()


@pytest.mark.asyncio
async def test_monitor_stopped_on_close() -> None:
    """async_close stops a running interface monitor."""
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    zc = aiozc.zeroconf
    await zc.async_wait_for_start()
    with patch.object(im, "_adapter_snapshot", return_value=frozenset()):
        await aiozc.async_start_interface_monitor(interval=10)
    assert zc._interface_monitor is not None
    await aiozc.async_close()
    assert zc._interface_monitor is None
