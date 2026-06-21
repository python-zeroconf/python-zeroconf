"""Optional periodic interface-change monitor.

Interface change detection is platform specific and is left to the consumer
by default. This convenience monitor polls ``ifaddr.get_adapters`` and calls
``Zeroconf.async_update_interfaces`` when the set of interface addresses
changes, so a consumer that has no native change signal can still reconcile
sockets without restarting the instance.
"""

from __future__ import annotations

import asyncio
import contextlib
from typing import TYPE_CHECKING

import ifaddr

from .._logger import log

if TYPE_CHECKING:
    from .._core import Zeroconf

_DEFAULT_INTERFACE_MONITOR_INTERVAL = 5.0  # seconds


def _adapter_snapshot() -> frozenset[tuple[int | None, str]]:
    """Return a hashable snapshot of every adapter index and address."""
    return frozenset((adapter.index, str(ip.ip)) for adapter in ifaddr.get_adapters() for ip in adapter.ips)


class InterfaceMonitor:
    """Poll for adapter changes and rescan interfaces when they change."""

    __slots__ = ("_interval", "_snapshot", "_task", "_zc")

    def __init__(self, zc: Zeroconf, interval: float = _DEFAULT_INTERFACE_MONITOR_INTERVAL) -> None:
        self._zc = zc
        self._interval = interval
        self._snapshot = _adapter_snapshot()
        self._task: asyncio.Task[None] | None = None

    def start(self) -> None:
        """Start the poll task on the running loop."""
        assert self._zc.loop is not None
        if self._task is None:
            self._task = self._zc.loop.create_task(self._async_run())

    async def async_stop(self) -> None:
        """Cancel the poll task and wait for it to finish."""
        task = self._task
        if task is None:
            return
        self._task = None
        task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await task

    async def _async_run(self) -> None:
        """Rescan interfaces whenever the adapter snapshot changes."""
        while True:
            await asyncio.sleep(self._interval)
            snapshot = _adapter_snapshot()
            if snapshot == self._snapshot:
                continue
            self._snapshot = snapshot
            try:
                await self._zc.async_update_interfaces()
            except Exception:
                # A transient failure must not kill the monitor; the next
                # change still triggers a rescan.
                log.exception("Interface rescan failed")
