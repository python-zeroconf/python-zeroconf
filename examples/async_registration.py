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

    async def register_services(self, infos: List[AsyncServiceInfo]) -> None:
        self.aiozc = AsyncZeroconf(ip_version=self.ip_version)
        tasks = [self.aiozc.async_register_service(info) for info in infos]
        background_tasks = await asyncio.gather(*tasks)
        await asyncio.gather(*background_tasks)
        print("Finished registration, press Ctrl-C to exit...")
        while True:
            await asyncio.sleep(1)

    async def unregister_services(self, infos: List[AsyncServiceInfo]) -> None:
        assert self.aiozc is not None
        tasks = [self.aiozc.async_unregister_service(info) for info in infos]
        background_tasks = await asyncio.gather(*tasks)
        await asyncio.gather(*background_tasks)
        await self.aiozc.async_close()
        print("\nClosed")


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

    desc = [{'dummy': 'abcd', 'thread-test': 'a49'},
            {'a': '2', 'thread-test': 'b50_test'},
            {'a_dummy': '42', 'thread-test': ''},
            {'thread-test': '1', 'ignorethis': 'thread-test='},
            {'a88': 'thread-', 'THREAD-TEST': 'C51', 'ignorethis': 'thread-test'},]

    infos = []
    for i in range(1,6):
        infos.append(
            AsyncServiceInfo(
                "_infra-test._udp.local.",
                f"service-test-{i}._infra-test._udp.local.",
                addresses=[socket.inet_pton(socket.AF_INET6,"fe80::6770:70:d014:327"), socket.inet_pton(socket.AF_INET6,"fd40:591:1750:102e:4f65:7721:b7e8:8419")],
                port=55550+i,
                properties=desc[i-1],
                server="host-test-eth.local.",
            )
        )

    print("Registration of 250 services...")
    loop = asyncio.get_event_loop()
    runner = AsyncRunner(ip_version)
    try:
        loop.run_until_complete(runner.register_services(infos))
    except KeyboardInterrupt:
        loop.run_until_complete(runner.unregister_services(infos))
