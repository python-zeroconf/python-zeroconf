#!/usr/bin/env python

"""Scan for Apple devices and dump the device info records they advertise."""

from __future__ import annotations

import argparse
import asyncio
import contextlib
import logging
from typing import Any

from zeroconf import DNSQuestionType, IPVersion, ServiceStateChange, Zeroconf
from zeroconf.asyncio import AsyncServiceBrowser, AsyncServiceInfo, AsyncZeroconf

HAP_TYPE = "_hap._tcp.local."
DEVICE_INFO_TYPE = "_device-info._tcp.local."

log = logging.getLogger(__name__)

_background_tasks: set[asyncio.Task] = set()


def on_service_state_change(
    zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
) -> None:
    print(f"{state_change.name}: {name}")
    if state_change is not ServiceStateChange.Added:
        return
    task = asyncio.create_task(dump_service_info(zeroconf, service_type, name))
    _background_tasks.add(task)
    task.add_done_callback(_background_tasks.discard)


async def dump_service_info(zeroconf: Zeroconf, service_type: str, name: str) -> None:
    info = AsyncServiceInfo(service_type, name)
    if not await info.async_request(zeroconf, 3000, question_type=DNSQuestionType.QU):
        print(f"  {name}: no response")
        return
    show_info(info)
    device_name = f"{info.server.rstrip('.')}.{DEVICE_INFO_TYPE}" if info.server else None
    if device_name:
        device_info = AsyncServiceInfo(DEVICE_INFO_TYPE, device_name)
        if await device_info.async_request(zeroconf, 3000, question_type=DNSQuestionType.QU):
            show_info(device_info)


def show_info(info: AsyncServiceInfo) -> None:
    print(f"  {info.name}")
    print(f"    reachable at: {', '.join(info.parsed_scoped_addresses())}")
    print(f"    host {info.server} port {info.port} (priority {info.priority}, weight {info.weight})")
    for key, value in info.decoded_properties.items():
        if not key:
            continue
        print(f"    txt {key} = {value}")


async def main(args: Any) -> None:
    ip_version = IPVersion.V6Only if args.v6_only else IPVersion.All
    aiozc = AsyncZeroconf(ip_version=ip_version)
    browser = AsyncServiceBrowser(aiozc.zeroconf, HAP_TYPE, handlers=[on_service_state_change])
    print(f"scanning for {HAP_TYPE}, press ctrl-c to exit")
    try:
        await asyncio.Event().wait()
    finally:
        await browser.async_cancel()
        await aiozc.async_close()


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--debug", action="store_true", help="enable debug logging")
    parser.add_argument("--v6-only", action="store_true", help="use IPv6 only")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)

    with contextlib.suppress(KeyboardInterrupt):
        asyncio.run(main(args))
