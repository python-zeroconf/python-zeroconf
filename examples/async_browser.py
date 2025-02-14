#!/usr/bin/env python

"""Example of browsing for a service.

The default is HTTP and HAP; use --find to search for all available services in the network
"""

from __future__ import annotations

import argparse
import asyncio
import logging
from typing import Any, cast

from zeroconf import IPVersion, ServiceStateChange, Zeroconf
from zeroconf.asyncio import (
    AsyncServiceBrowser,
    AsyncServiceInfo,
    AsyncZeroconf,
    AsyncZeroconfServiceTypes,
)

_PENDING_TASKS: set[asyncio.Task] = set()


def async_on_service_state_change(
    zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
) -> None:
    print(f"Service {name} of type {service_type} state changed: {state_change}")
    if state_change is not ServiceStateChange.Added:
        return
    task = asyncio.ensure_future(async_display_service_info(zeroconf, service_type, name))
    _PENDING_TASKS.add(task)
    task.add_done_callback(_PENDING_TASKS.discard)


async def async_display_service_info(zeroconf: Zeroconf, service_type: str, name: str) -> None:
    info = AsyncServiceInfo(service_type, name)
    await info.async_request(zeroconf, 3000)
    print(f"Info from zeroconf.get_service_info: {info!r}")
    if info:
        addresses = [f"{addr}:{cast(int, info.port)}" for addr in info.parsed_scoped_addresses()]
        print(f"  Name: {name}")
        print(f"  Addresses: {', '.join(addresses)}")
        print(f"  Weight: {info.weight}, priority: {info.priority}")
        print(f"  Server: {info.server}")
        if info.properties:
            print("  Properties are:")
            for key, value in info.properties.items():
                print(f"    {key!r}: {value!r}")
        else:
            print("  No properties")
    else:
        print("  No info")
    print("\n")


class AsyncRunner:
    def __init__(self, args: Any) -> None:
        self.args = args
        self.aiobrowser: AsyncServiceBrowser | None = None
        self.aiozc: AsyncZeroconf | None = None

    async def async_run(self) -> None:
        self.aiozc = AsyncZeroconf(ip_version=ip_version)

        services = ["_http._tcp.local.", "_hap._tcp.local."]
        if self.args.find:
            services = list(
                await AsyncZeroconfServiceTypes.async_find(aiozc=self.aiozc, ip_version=ip_version)
            )

        print(f"\nBrowsing {services} service(s), press Ctrl-C to exit...\n")
        self.aiobrowser = AsyncServiceBrowser(
            self.aiozc.zeroconf, services, handlers=[async_on_service_state_change]
        )
        await asyncio.Event().wait()

    async def async_close(self) -> None:
        assert self.aiozc is not None
        assert self.aiobrowser is not None
        await self.aiobrowser.async_cancel()
        await self.aiozc.async_close()


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--find", action="store_true", help="Browse all available services")
    version_group = parser.add_mutually_exclusive_group()
    version_group.add_argument("--v6", action="store_true")
    version_group.add_argument("--v6-only", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger("zeroconf").setLevel(logging.DEBUG)
    if args.v6:
        ip_version = IPVersion.All
    elif args.v6_only:
        ip_version = IPVersion.V6Only
    else:
        ip_version = IPVersion.V4Only

    loop = asyncio.get_event_loop()
    runner = AsyncRunner(args)
    try:
        loop.run_until_complete(runner.async_run())
    except KeyboardInterrupt:
        loop.run_until_complete(runner.async_close())
