""" Multicast DNS Service Discovery for Python, v0.11
    Copyright (C) 2003, Paul Scott-Murphy

    This module provides a unit test suite for the Multicast DNS
    Service Discovery for Python module.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA 02111-1307 USA
	
"""

__author__ = "Paul Scott-Murphy"
__email__ = "paul at scott dash murphy dot com"
__version__ = "0.12"

from Zeroconf import *
import socket

desc = {'path':'/~paulsm/'}
info = ServiceInfo("_http._tcp.local.", "Paul's Test Web Site._http._tcp.local.", socket.inet_aton("10.0.1.2"), 80, 0, 0, desc, "ash-2.local.")

r = Zeroconf()
print "Registration of a service..."
r.registerService(info)
print "Waiting..."
