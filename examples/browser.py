#!/usr/bin/env python

"""Browse for HTTP services with the synchronous API and print each event."""

from __future__ import annotations

import argparse
import logging

from zeroconf import IPVersion, ServiceBrowser, ServiceListener, Zeroconf


class PrintingListener(ServiceListener):
    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        info = zc.get_service_info(type_, name)
        print(f"added: {name}")
        if info is not None:
            print(f"  addresses: {', '.join(info.parsed_scoped_addresses())}")
            print(f"  server: {info.server} port: {info.port}")
            print(f"  properties: {info.decoded_properties}")

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f"removed: {name}")

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        print(f"updated: {name}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--debug", action="store_true", help="enable debug logging")
    parser.add_argument("--v6-only", action="store_true", help="use IPv6 only")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    ip_version = IPVersion.V6Only if args.v6_only else IPVersion.All

    zc = Zeroconf(ip_version=ip_version)
    browser = ServiceBrowser(zc, "_http._tcp.local.", PrintingListener())
    print("browsing for _http._tcp.local., press enter to exit")
    try:
        input()
    finally:
        zc.close()
