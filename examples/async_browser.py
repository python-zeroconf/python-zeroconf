#!/usr/bin/env python3

""" Example of browsing for a service.

The default is HTTP and HAP; use --find to search for all available services in the network
"""

import argparse
import asyncio
import logging
from typing import cast

from zeroconf import IPVersion, ServiceStateChange
from zeroconf.asyncio import AsyncServiceBrowser, AsyncZeroconf


def async_on_service_state_change(
    zeroconf: AsyncZeroconf, service_type: str, name: str, state_change: ServiceStateChange
) -> None:
    print("Service %s of type %s state changed: %s" % (name, service_type, state_change))
    if state_change is not ServiceStateChange.Added:
        return
    asyncio.ensure_future(async_display_service_info(zeroconf, service_type, name))


async def async_display_service_info(zeroconf: AsyncZeroconf, service_type: str, name: str) -> None:
    info = await zeroconf.async_get_service_info(service_type, name)
    print("Info from zeroconf.get_service_info: %r" % (info))
    if info:
        addresses = ["%s:%d" % (addr, cast(int, info.port)) for addr in info.parsed_addresses()]
        print("  Name: %s" % name)
        print("  Addresses: %s" % ", ".join(addresses))
        print("  Weight: %d, priority: %d" % (info.weight, info.priority))
        print("  Server: %s" % (info.server,))
        if info.properties:
            print("  Properties are:")
            for key, value in info.properties.items():
                print("    %s: %s" % (key, value))
        else:
            print("  No properties")
    else:
        print("  No info")
    print('\n')


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

    aiozc = AsyncZeroconf(ip_version=ip_version)

    services = ["_http._tcp.local.", "_hap._tcp.local."]
    print("\nBrowsing %s service(s), press Ctrl-C to exit...\n" % services)
    aiobrowser = AsyncServiceBrowser(aiozc, services, handlers=[async_on_service_state_change])

    loop = asyncio.get_event_loop()
    try:
        loop.run_forever()
    except KeyboardInterrupt:
        pass
    finally:
        loop.run_until_complete(aiobrowser.async_cancel())
        loop.run_until_complete(aiozc.async_close())
