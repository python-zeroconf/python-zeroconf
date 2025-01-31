#!/usr/bin/env python

"""Example of browsing for a service.

The default is HTTP and HAP; use --find to search for all available services in the network
"""

from __future__ import annotations

import argparse
import logging
from time import sleep
from typing import cast

from zeroconf import (
    IPVersion,
    ServiceBrowser,
    ServiceStateChange,
    Zeroconf,
    ZeroconfServiceTypes,
)


def on_service_state_change(
    zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
) -> None:
    print(f"Service {name} of type {service_type} state changed: {state_change}")

    if state_change is ServiceStateChange.Added:
        info = zeroconf.get_service_info(service_type, name)
        print(f"Info from zeroconf.get_service_info: {info!r}")

        if info:
            addresses = [f"{addr}:{cast(int, info.port)}" for addr in info.parsed_scoped_addresses()]
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


if __name__ == "__main__":
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument("--debug", action="store_true")
    parser.add_argument("--find", action="store_true", help="Browse all available services")
    version_group = parser.add_mutually_exclusive_group()
    version_group.add_argument("--v6-only", action="store_true")
    version_group.add_argument("--v4-only", action="store_true")
    args = parser.parse_args()

    if args.debug:
        logging.getLogger("zeroconf").setLevel(logging.DEBUG)
    if args.v6_only:
        ip_version = IPVersion.V6Only
    elif args.v4_only:
        ip_version = IPVersion.V4Only
    else:
        ip_version = IPVersion.All

    zeroconf = Zeroconf(ip_version=ip_version)

    services = [
        "_http._tcp.local.",
        "_hap._tcp.local.",
        "_esphomelib._tcp.local.",
        "_airplay._tcp.local.",
    ]
    if args.find:
        services = list(ZeroconfServiceTypes.find(zc=zeroconf))

    print(f"\nBrowsing {len(services)} service(s), press Ctrl-C to exit...\n")
    browser = ServiceBrowser(zeroconf, services, handlers=[on_service_state_change])

    try:
        while True:
            sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        zeroconf.close()
