#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals

""" Example of browsing for a service (in this case, HTTP) """

import logging
import socket
import sys
from time import sleep

from zeroconf import ServiceBrowser, Zeroconf


class MyListener(object):

    def remove_service(self, zeroconf, type, name):
        print("Service %s removed" % (name,))
        print('\n')

    def add_service(self, zeroconf, type, name):
        print("Service %s added" % (name,))
        print("  Type is %s" % (type,))
        info = zeroconf.get_service_info(type, name)
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
    if len(sys.argv) > 1:
        assert sys.argv[1:] == ['--debug']
        logging.getLogger('zeroconf').setLevel(logging.DEBUG)

    zeroconf = Zeroconf()
    print("\nBrowsing services, press Ctrl-C to exit...\n")
    listener = MyListener()
    browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
    try:
        while True:
            sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        zeroconf.close()
