#!/usr/bin/env python3
"""Example of announcing 250 services (in this case, a fake HTTP server)."""

import argparse
import asyncio
import logging
import socket
from typing import List, Optional

from zeroconf import IPVersion
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf


class AsyncRunner:
    def __init__(self, ip_version: IPVersion) -> None:
        self.ip_version = ip_version
        self.aiozc: Optional[AsyncZeroconf] = None

    async def test_mcast(self) -> None:
        self.aiozc = AsyncZeroconf(ip_version=self.ip_version)
        info = await self.aiozc.async_get_service_info(
            "_home-assistant._tcp.local.", "Defend-2._home-assistant._tcp.local.", timeout=5000
        )
        import pprint

        pprint.pprint(info)
        await self.aiozc.async_close()


if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    version_group = parser.add_mutually_exclusive_group()
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

    print("Registration of 250 services...")
    loop = asyncio.get_event_loop()
    runner = AsyncRunner(ip_version)
    loop.run_until_complete(runner.test_mcast())
