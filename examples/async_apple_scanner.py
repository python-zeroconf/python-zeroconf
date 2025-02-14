#!/usr/bin/env python

"""Scan for apple devices."""

from __future__ import annotations

import argparse
import asyncio
import logging
from typing import Any, cast

from zeroconf import DNSQuestionType, IPVersion, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

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

_PENDING_TASKS: set[asyncio.Task] = set()


def async_on_service_state_change(
    zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
) -> None:
    print(f"Service {name} of type {service_type} state changed: {state_change}")
    if state_change is not ServiceStateChange.Added:
        return
    base_name = name[: -len(service_type) - 1]
    device_name = f"{base_name}.{DEVICE_INFO_SERVICE}"
    task = asyncio.ensure_future(_async_show_service_info(zeroconf, service_type, name))
    _PENDING_TASKS.add(task)
    task.add_done_callback(_PENDING_TASKS.discard)
    # Also probe for device info
    task = asyncio.ensure_future(_async_show_service_info(zeroconf, DEVICE_INFO_SERVICE, device_name))
    _PENDING_TASKS.add(task)
    task.add_done_callback(_PENDING_TASKS.discard)


async def _async_show_service_info(zeroconf: Zeroconf, service_type: str, name: str) -> None:
    info = AsyncServiceInfo(service_type, name)
    await info.async_request(zeroconf, 3000, question_type=DNSQuestionType.QU)
    print(f"Info from zeroconf.get_service_info: {info!r}")
    if info:
        addresses = [f"{addr}:{cast(int, info.port)}" for addr in info.parsed_addresses()]
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


class AsyncAppleScanner:
    def __init__(self, args: Any) -> None:
        self.args = args
        self.aiobrowser: AsyncServiceBrowser | None = None
        self.aiozc: AsyncZeroconf | None = None

    async def async_run(self) -> None:
        self.aiozc = AsyncZeroconf(ip_version=ip_version)
        await self.aiozc.zeroconf.async_wait_for_start()
        print(f"\nBrowsing {ALL_SERVICES} service(s), press Ctrl-C to exit...\n")
        kwargs = {
            "handlers": [async_on_service_state_change],
            "question_type": DNSQuestionType.QU,
        }
        if self.args.target:
            kwargs["addr"] = self.args.target
        self.aiobrowser = AsyncServiceBrowser(
            self.aiozc.zeroconf,
            ALL_SERVICES,
            **kwargs,  # type: ignore[arg-type]
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
    version_group = parser.add_mutually_exclusive_group()
    version_group.add_argument("--target", help="Unicast target")
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
    runner = AsyncAppleScanner(args)
    try:
        loop.run_until_complete(runner.async_run())
    except KeyboardInterrupt:
        loop.run_until_complete(runner.async_close())
