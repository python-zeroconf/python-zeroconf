#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals

""" Example of browsing for a service (in this case, HTTP) """

import socket

from six.moves import input

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
    zeroconf = Zeroconf()
    print("Browsing services...")
    listener = MyListener()
    browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
    try:
        input("Waiting (press Enter to exit)...\n\n")
    finally:
        zeroconf.close()
