#!/usr/bin/env python

"""Register a demo HTTP service and keep it announced until interrupted."""

from __future__ import annotations

import argparse
import logging
import socket
from time import sleep

from zeroconf import IPVersion, ServiceInfo, Zeroconf

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--debug", action="store_true", help="enable debug logging")
    parser.add_argument("--v6-only", action="store_true", help="use IPv6 only")
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.debug else logging.INFO)
    ip_version = IPVersion.V6Only if args.v6_only else IPVersion.All

    service = ServiceInfo(
        "_http._tcp.local.",
        "Demo Web Service._http._tcp.local.",
        addresses=[socket.inet_aton("127.0.0.1")],
        port=8080,
        properties={"path": "/"},
        server="demo-host.local.",
    )

    zc = Zeroconf(ip_version=ip_version)
    print("registering Demo Web Service._http._tcp.local., press ctrl-c to exit")
    zc.register_service(service)
    try:
        while True:
            sleep(0.5)
    except KeyboardInterrupt:
        pass
    finally:
        print("unregistering")
        zc.unregister_service(service)
        zc.close()
