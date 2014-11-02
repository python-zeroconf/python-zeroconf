#!/usr/bin/env python

""" Example of announcing a service (in this case, a fake HTTP server) """

import socket

from zeroconf import raw_input, ServiceInfo, Zeroconf

desc = {'path': '/~paulsm/'}

info = ServiceInfo("_http._tcp.local.",
                   "Paul's Test Web Site._http._tcp.local.",
                   socket.inet_aton("10.0.1.2"), 80, 0, 0,
                   desc, "ash-2.local.")

zeroconf = Zeroconf()
print("Registration of a service...")
zeroconf.register_service(info)
try:
    raw_input("Waiting (press Enter to exit)...")
finally:
    print("Unregistering...")
    zeroconf.unregister_service(info)
    zeroconf.close()
