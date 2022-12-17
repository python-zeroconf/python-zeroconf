#!/usr/bin/env python3
"""Example of perodic dump of homekit services.

This example is useful when a user wants an ondemand
list of HomeKit devices on the network.

"""

import argparse
import asyncio
import logging
from typing import Any, Optional, cast

from zeroconf import IPVersion, ServiceBrowser, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf

HAP_TYPE = "_hap._tcp.local."


async def async_watch_services(aiozc: AsyncZeroconf) -> None:
    zeroconf = aiozc.zeroconf
    while True:
        await asyncio.sleep(5)
        infos = []
        for name in zeroconf.cache.names():
            if not name.endswith(HAP_TYPE):
                continue
            infos.append(AsyncServiceInfo(HAP_TYPE, name))
        tasks = [info.async_request(aiozc.zeroconf, 3000) for info in infos]
        await asyncio.gather(*tasks)
        for info in infos:
            print("Info for %s" % (info.name))
            if info:
                addresses = ["%s:%d" % (addr, cast(int, info.port)) for addr in info.parsed_addresses()]
                print("  Addresses: %s" % ", ".join(addresses))
                print("  Weight: %d, priority: %d" % (info.weight, info.priority))
                print(f"  Server: {info.server}")
                if info.properties:
                    print("  Properties are:")
                    for key, value in info.properties.items():
                        print(f"    {key}: {value}")
                else:
                    print("  No properties")
            else:
                print("  No info")
            print('\n')


class AsyncRunner:
    def __init__(self, args: Any) -> None:
        self.args = args
        self.threaded_browser: Optional[ServiceBrowser] = None
        self.aiozc: Optional[AsyncZeroconf] = None

    async def async_run(self) -> None:
        self.aiozc = AsyncZeroconf(ip_version=ip_version)
        assert self.aiozc is not None

        def on_service_state_change(
            zeroconf: Zeroconf, service_type: str, state_change: ServiceStateChange, name: str
        ) -> None:
            """Dummy handler."""

        self.threaded_browser = ServiceBrowser(
            self.aiozc.zeroconf, [HAP_TYPE], handlers=[on_service_state_change]
        )
        await async_watch_services(self.aiozc)

    async def async_close(self) -> None:
        assert self.aiozc is not None
        assert self.threaded_browser is not None
        self.threaded_browser.cancel()
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

    print(f"Services with {HAP_TYPE} will be shown every 5s, press Ctrl-C to exit...")
    loop = asyncio.get_event_loop()
    runner = AsyncRunner(args)
    try:
        loop.run_until_complete(runner.async_run())
    except KeyboardInterrupt:
        loop.run_until_complete(runner.async_close())
