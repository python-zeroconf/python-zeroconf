#!/usr/bin/env python
from __future__ import absolute_import, division, print_function, unicode_literals
""" Example of resolving local hosts"""
# a stripped down verssion of browser.py example
# zeroconf may have issues with ipv6 addresses and mixed case hostnames
from time import sleep
import sys
from zeroconf import ServiceBrowser, ServiceStateChange, Zeroconf,DNSAddress

def on_service_state_change(zeroconf, service_type, name, state_change):
    if state_change is ServiceStateChange.Added:
        zeroconf.get_service_info(service_type, name)

zeroconf = Zeroconf()
ServiceBrowser(zeroconf, "_workstation._tcp.local.", handlers=[on_service_state_change])
ServiceBrowser(zeroconf, "_telnet._tcp.local.", handlers=[on_service_state_change])
ServiceBrowser(zeroconf, "_http._tcp.local.", handlers=[on_service_state_change])
ServiceBrowser(zeroconf, "_printer._tcp.local.", handlers=[on_service_state_change])
sleep(2)
#lookup specific host
if len(sys.argv)>1 :
   hostname=sys.argv[1]
   print(hostname,zeroconf.cache.entries_with_name(hostname))
cache=zeroconf.cache.cache
zeroconf.close()
# list all known hosts in .local
for key in cache.keys():
    if isinstance(cache[key][0],DNSAddress):
       print(key,cache[key])
sleep(1)

