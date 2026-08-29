#!/usr/bin/env python

"""Register a batch of demo HTTP services with the asyncio API."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
import socket

from zeroconf import IPVersion, ServiceInfo
from zeroconf.asyncio import AsyncZeroconf

SERVICE_COUNT = 250


def build_services() -> list[ServiceInfo]:
    return [
        ServiceInfo(
            "_http._tcp.local.",
            f"Demo Web Service {i}._http._tcp.local.",
            addresses=[socket.inet_aton("127.0.0.1")],
            port=8080 + i,
            properties={"path": "/"},
            server=f"demo-host-{i}.local.",
        )
        for i in range(SERVICE_COUNT)
    ]


async def main(ip_version: IPVersion) -> None:
    aiozc = AsyncZeroconf(ip_version=ip_version)
    services = build_services()
    print(f"registering {len(services)} demo services, press ctrl-c to exit")
    background_tasks = await asyncio.gather(*(aiozc.async_register_service(service) for service in services))
    await asyncio.gather(*background_tasks)
    try:
        await asyncio.Event().wait()
    finally:
        print("unregistering")
        unregister_tasks = await asyncio.gather(
            *(aiozc.async_unregister_service(service) for service in services)
        )
        await asyncio.gather(*unregister_tasks)
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
