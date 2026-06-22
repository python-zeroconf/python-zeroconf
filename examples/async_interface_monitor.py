#!/usr/bin/env python

"""Re-announce services when the host's network interfaces change.

``AsyncZeroconf.async_update_interfaces()`` reconciles the sockets in use to the
live interface set: it binds responders for interfaces that appeared, tears down
the ones that went away, and re-announces existing registrations on the new
senders. A call where nothing changed is a no-op.

zeroconf does not poll for interface changes itself; detection is
platform-specific and is best driven from whatever signal a host already has (a
netlink subscription on Linux, a framework's adapter-change event, etc.). When
no such signal is available, a small periodic poller like the one below is
enough: snapshot the addresses and reconcile only when they change. The piece
worth copying carefully is the lifecycle, cancel the monitor task before
closing the AsyncZeroconf so it does not outlive the instance.
"""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging

import ifaddr

from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

_LOGGER = logging.getLogger("interface_monitor")


def address_snapshot() -> set[tuple[str, int]]:
    """A snapshot of the host's current addresses; a change triggers a reconcile."""
    return {(str(ip.ip), ip.network_prefix) for adapter in ifaddr.get_adapters() for ip in adapter.ips}


async def monitor_interfaces(aiozc: AsyncZeroconf, interval: float) -> None:
    """Reconcile sockets whenever the host's addresses change, until cancelled."""
    previous = address_snapshot()
    while True:
        await asyncio.sleep(interval)
        current = address_snapshot()
        if current == previous:
            continue
        try:
            print("Interfaces changed, reconciling sockets...")
            await aiozc.async_update_interfaces()
        except Exception:
            # Log and retry on the next tick rather than letting the monitor
            # die; leave ``previous`` unchanged so the change is re-attempted.
            _LOGGER.exception("Interface reconcile failed; will retry")
        else:
            previous = current


class AsyncRunner:
    def __init__(self) -> None:
        self.aiozc: AsyncZeroconf | None = None
        self.monitor: asyncio.Task | None = None

    async def run(self, info: AsyncServiceInfo, interval: float) -> None:
        self.aiozc = AsyncZeroconf()
        await self.aiozc.async_register_service(info)
        self.monitor = asyncio.create_task(monitor_interfaces(self.aiozc, interval))
        print("Registered; monitoring interfaces. Press Ctrl-C to exit...")
        await asyncio.Event().wait()

    async def close(self, info: AsyncServiceInfo) -> None:
        assert self.aiozc is not None
        # Stop the monitor before closing so it can't reconcile a closed instance.
        if self.monitor is not None:
            self.monitor.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self.monitor
        # Await the goodbye broadcast so the TTL-0 records are actually sent.
        await (await self.aiozc.async_unregister_service(info))
        await self.aiozc.async_close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.INFO)

    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--interval", type=float, default=30.0, help="poll seconds")
    args = parser.parse_args()
    if args.debug:
        logging.getLogger("zeroconf").setLevel(logging.DEBUG)

    info = AsyncServiceInfo(
        "_http._tcp.local.",
        "Interface Monitor Demo._http._tcp.local.",
        port=80,
        properties={"path": "/"},
        server="interface-monitor-demo.local.",
    )

    loop = asyncio.get_event_loop()
    runner = AsyncRunner()
    try:
        loop.run_until_complete(runner.run(info, args.interval))
    except KeyboardInterrupt:
        loop.run_until_complete(runner.close(info))
