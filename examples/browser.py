#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals

""" Example of browsing for a service (in this case, HTTP) """

import logging
import socket
from time import sleep

from zeroconf import ServiceBrowser, ServiceStateChange, Zeroconf


def on_service_state_change(zeroconf, service_type, name, state_change):
    print("Service %s of type %s state changed: %s" % (name, service_type, state_change))

    if state_change is ServiceStateChange.Added:
        info = zeroconf.get_service_info(service_type, name)
        if info:
            print("  Address is %s:%d" % (socket.inet_ntoa(info.address),
                                          info.port))
            print("  Weight is %d, Priority is %d" % (info.weight,
                                                      info.priority))
            print("  Server is", info.server)
            if info.properties:
                print("  Properties are")
                for key, value in info.properties.items():
                    print("    %s: %s" % (key, value))
        else:
            print("  No info")
        print('\n')

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    logging.getLogger('zeroconf').setLevel(logging.DEBUG)

    zeroconf = Zeroconf()
    print("\nBrowsing services, press Ctrl-C to exit...\n")
    browser = ServiceBrowser(zeroconf, "_http._tcp.local.", handlers=[on_service_state_change])

    try:
        while True:
            sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        zeroconf.close()
