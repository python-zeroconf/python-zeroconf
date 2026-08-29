#!/usr/bin/env python

"""Resolve every HTTP service currently on the network, on a fixed cadence."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging

from zeroconf import IPVersion, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

HTTP_TYPE = "_http._tcp.local."
RESOLVE_INTERVAL = 5


async def resolve_all(zeroconf: Zeroconf, names: set[str]) -> None:
    infos = [AsyncServiceInfo(HTTP_TYPE, name) for name in sorted(names)]
    await asyncio.gather(*(info.async_request(zeroconf, 3000) for info in infos))
    for info in infos:
        print(f"  {info.name}")
        if not info.server:
            print("    (unresolved)")
            continue
        print(f"    reachable at: {', '.join(info.parsed_scoped_addresses())}")
        print(f"    host {info.server} port {info.port} (priority {info.priority}, weight {info.weight})")
        for key, value in info.decoded_properties.items():
            if not key:
                continue
            print(f"    txt {key} = {value}")


async def main(ip_version: IPVersion) -> None:
    seen: set[str] = set()
    aiozc = AsyncZeroconf(ip_version=ip_version)
    browser = AsyncServiceBrowser(
        aiozc.zeroconf,
        HTTP_TYPE,
        handlers=[lambda zeroconf, service_type, name, state_change: seen.add(name)],
    )
    print(f"collecting {HTTP_TYPE} services, resolving every {RESOLVE_INTERVAL}s; ctrl-c to exit")
    try:
        while True:
            await asyncio.sleep(RESOLVE_INTERVAL)
            print(f"resolving {len(seen)} known services:")
            await resolve_all(aiozc.zeroconf, seen)
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
