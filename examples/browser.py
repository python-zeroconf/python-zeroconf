#!/usr/bin/env python3

USE="""usage: example.py [--help] [--debug] [--find]

Scan network for available mDNS services.

  --help     This help
  --debug    Set logging level to DEBUG
  --find     Browse all available services:
    """
SVC="\n    "

import logging
import socket
import sys
from time import sleep
from typing import cast

from zeroconf import ServiceBrowser, ServiceStateChange, Zeroconf, ZeroconfServiceTypes


def on_service_state_change(
    zeroconf: Zeroconf, service_type: str, name: str, state_change: ServiceStateChange
) -> None:
    print("Service %s of type %s state changed: %s" % (name, service_type, state_change))

    if state_change is ServiceStateChange.Added:
        info = zeroconf.get_service_info(service_type, name)
        if info:
            addresses = ["%s:%d" % (socket.inet_ntoa(addr), cast(int, info.port)) for addr in info.addresses]
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
    if '--debug' in sys.argv[1:]:
        logging.getLogger('zeroconf').setLevel(logging.DEBUG)

    zeroconf = Zeroconf()
    services = ("_http._tcp.local.",)
    if '--find' in sys.argv[1:]:
        services = ZeroconfServiceTypes.find(zc=zeroconf)
    if '--help' in sys.argv[1:]:
        print(USE + (SVC.join( services )))
        sys.exit(0)

    print("\nBrowsing %d service(s), press Ctrl-C to exit...\n" % len(services))
    for service_type in services:
        ServiceBrowser(zeroconf, service_type, handlers=[on_service_state_change])

    try:
        while True:
            sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        zeroconf.close()
