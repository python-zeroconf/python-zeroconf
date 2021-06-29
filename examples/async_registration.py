#!/usr/bin/env python3
"""Example of announcing 250 services (in this case, a fake HTTP server)."""

import argparse
import asyncio
import logging
import socket
import time
from typing import List

from zeroconf import IPVersion
from zeroconf.asyncio import AsyncServiceInfo, AsyncZeroconf


async def register_services(infos: List[AsyncServiceInfo]) -> None:
    tasks = [aiozc.async_register_service(info) for info in infos]
    background_tasks = await asyncio.gather(*tasks)
    await asyncio.gather(*background_tasks)


async def unregister_services(infos: List[AsyncServiceInfo]) -> None:
    tasks = [aiozc.async_unregister_service(info) for info in infos]
    background_tasks = await asyncio.gather(*tasks)
    await asyncio.gather(*background_tasks)


async def close_aiozc(aiozc: AsyncZeroconf) -> None:
    await aiozc.async_close()


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

    infos = []
    for i in range(250):
        infos.append(
            AsyncServiceInfo(
                "_http._tcp.local.",
                f"Paul's Test Web Site {i}._http._tcp.local.",
                addresses=[socket.inet_aton("127.0.0.1")],
                port=80,
                properties={'path': '/~paulsm/'},
                server=f"zcdemohost-{i}.local.",
            )
        )

    print("Registration of 250 services, press Ctrl-C to exit...")
    aiozc = AsyncZeroconf(ip_version=ip_version)
    loop = asyncio.get_event_loop()
    loop.run_until_complete(register_services(infos))
    print("Registration complete.")
    try:
        while True:
            time.sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        print("Unregistering...")
        loop.run_until_complete(unregister_services(infos))
        print("Unregistration complete.")
        loop.run_until_complete(close_aiozc(aiozc))
