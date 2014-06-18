from zeroconf import *
import socket

desc = {'path': '/~paulsm/'}

info = ServiceInfo("_http._tcp.local.",
                   "Paul's Test Web Site._http._tcp.local.",
                   socket.inet_aton("10.0.1.2"), 80, 0, 0,
                   desc, "ash-2.local.")

r = Zeroconf()
print "Registration of a service..."
r.registerService(info)
raw_input("Waiting (press Enter to exit)...")
print "Unregistering..."
r.unregisterService(info)
r.close()
