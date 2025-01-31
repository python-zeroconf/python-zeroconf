#!/usr/bin/env python

"""Example of resolving a name to an IP address."""

from __future__ import annotations

import asyncio
import logging
import sys

from zeroconf import AddressResolver, IPVersion
from zeroconf.asyncio import AsyncZeroconf


async def resolve_name(name: str) -> None:
    aiozc = AsyncZeroconf()
    await aiozc.zeroconf.async_wait_for_start()
    resolver = AddressResolver(name)
    if await resolver.async_request(aiozc.zeroconf, 3000):
        print(f"{name} IP addresses:", resolver.ip_addresses_by_version(IPVersion.All))
    else:
        print(f"Name {name} not resolved")
    await aiozc.async_close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)
    argv = sys.argv.copy()
    if "--debug" in argv:
        logging.getLogger("zeroconf").setLevel(logging.DEBUG)
        argv.remove("--debug")

    if len(argv) < 2 or not argv[1]:
        raise ValueError("Usage: resolve_address.py [--debug] <name>")

    name = argv[1]
    if not name.endswith("."):
        name += "."

    asyncio.run(resolve_name(name))
