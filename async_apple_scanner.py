#!/usr/bin/env python3

""" Scan for apple devices. """

import argparse
import asyncio
import logging
from typing import Any, Optional

from zeroconf import IPVersion, generate_service_query
from zeroconf.aio import AsyncServiceBrowser, AsyncZeroconf

HOMESHARING_SERVICE: str = "_appletv-v2._tcp.local."
DEVICE_SERVICE: str = "_touch-able._tcp.local."
MEDIAREMOTE_SERVICE: str = "_mediaremotetv._tcp.local."
AIRPLAY_SERVICE: str = "_airplay._tcp.local."
COMPANION_SERVICE: str = "_companion-link._tcp.local."
RAOP_SERVICE: str = "_raop._tcp.local."
AIRPORT_ADMIN_SERVICE: str = "_airport._tcp.local."
DEVICE_INFO_SERVICE: str = "_device-info._tcp.local."

ALL_SERVICES = [
    HOMESHARING_SERVICE,
    DEVICE_SERVICE,
    MEDIAREMOTE_SERVICE,
    AIRPLAY_SERVICE,
    COMPANION_SERVICE,
    RAOP_SERVICE,
    AIRPORT_ADMIN_SERVICE,
    DEVICE_INFO_SERVICE,
]

log = logging.getLogger(__name__)


class AsyncAppleScanner:
    def __init__(self, args: Any) -> None:
        self.args = args
        self.aiozc: Optional[AsyncZeroconf] = None

    async def async_run(self) -> None:
        self.aiozc = AsyncZeroconf(ip_version=ip_version)
        await self.aiozc.zeroconf.async_wait_for_start()
        target = self.args.target or None
        multicast = not target
        include_known_answers = not target
        outgoings = generate_service_query(
            self.aiozc.zeroconf, ALL_SERVICES, multicast, include_known_answers
        )
        for outgoing in outgoings:
            log.debug("Sending %s to %s", outgoing, target)
            self.aiozc.zeroconf.async_send(outgoing, target)

        while True:
            await self.aiozc.async_wait(1000)
            # Dump the cache -- for example only, Install an AsyncServiceListener instead
            import pprint

            pprint.pprint(self.aiozc.zeroconf.cache.cache)

    async def async_close(self) -> None:
        assert self.aiozc is not None
        await self.aiozc.async_close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    version_group = parser.add_mutually_exclusive_group()
    version_group.add_argument('--target', help='Unicast target')
    version_group.add_argument('--v6', action='store_true')
    version_group.add_argument('--v6-only', action='store_true')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger('zeroconf').setLevel(logging.DEBUG)
    if args.v6:
        ip_version = IPVersion.All
    elif args.v6_only:
        ip_version = IPVersion.V6Only
    else:
        ip_version = IPVersion.V4Only

    loop = asyncio.get_event_loop()
    runner = AsyncAppleScanner(args)
    try:
        loop.run_until_complete(runner.async_run())
    except KeyboardInterrupt:
        loop.run_until_complete(runner.async_close())
