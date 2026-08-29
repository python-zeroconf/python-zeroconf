#!/usr/bin/env python

"""Browse for HTTP services with the asyncio API and print each event."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging

from zeroconf import IPVersion, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

_background_tasks: set[asyncio.Task] = set()


def on_service_state_change(
    zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
) -> None:
    print(f"{state_change.name}: {name}")
    if state_change is ServiceStateChange.Added:
        task = asyncio.create_task(show_service_info(zeroconf, service_type, name))
        _background_tasks.add(task)
        task.add_done_callback(_background_tasks.discard)


async def show_service_info(zeroconf: Zeroconf, service_type: str, name: str) -> None:
    info = AsyncServiceInfo(service_type, name)
    if await info.async_request(zeroconf, 3000):
        print(f"  addresses: {', '.join(info.parsed_scoped_addresses())}")
        print(f"  server: {info.server} port: {info.port}")
        for key, value in info.decoded_properties.items():
            if key:
                print(f"  txt {key} = {value}")


async def main(ip_version: IPVersion) -> None:
    aiozc = AsyncZeroconf(ip_version=ip_version)
    browser = AsyncServiceBrowser(aiozc.zeroconf, "_http._tcp.local.", handlers=[on_service_state_change])
    print("browsing for _http._tcp.local., press ctrl-c to exit")
    try:
        await asyncio.Event().wait()
    finally:
        await browser.async_cancel()
        await aiozc.async_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--debug", action="store_true", help="enable debug logging")
    parser.add_argument("--v6-only", action="store_true", help="use IPv6 only")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    ip_version = IPVersion.V6Only if args.v6_only else IPVersion.All

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main(ip_version))
