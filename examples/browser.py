#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals

""" Example of browsing for a service (in this case, HTTP) """

import socket

from zeroconf import raw_input, ServiceBrowser, Zeroconf


class MyListener(object):

    def removeService(self, zeroconf, type, name):
        print("Service %s removed" % (name,))
        print('\n')

    def addService(self, zeroconf, type, name):
        print("Service %s added" % (name,))
        print("  Type is %s" % (type,))
        info = zeroconf.getServiceInfo(type, name)
        if info:
            print("  Address is %s:%d" % (socket.inet_ntoa(info.getAddress()),
                                          info.getPort()))
            print("  Weight is %d, Priority is %d" % (info.getWeight(),
                                                      info.getPriority()))
            print("  Server is", info.getServer())
            prop = info.getProperties()
            if prop:
                print("  Properties are")
                for key, value in prop.items():
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
        raw_input("Waiting (press Enter to exit)...\n\n")
    finally:
        zeroconf.close()
