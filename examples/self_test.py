#!/usr/bin/env python3

import logging
import socket
import sys

from zeroconf import ServiceInfo, Zeroconf, __version__

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)
    if len(sys.argv) > 1:
        assert sys.argv[1:] == ['--debug']
        logging.getLogger('zeroconf').setLevel(logging.DEBUG)

    # Test a few module features, including service registration, service
    # query (for Zoe), and service unregistration.
    print("Multicast DNS Service Discovery for Python, version %s" % (__version__,))
    r = Zeroconf()
    print("1. Testing registration of a service...")
    desc = {'version': '0.10', 'a': 'test value', 'b': 'another value'}
    addresses = [socket.inet_aton("127.0.0.1")]
    expected = {'127.0.0.1'}
    if socket.has_ipv6:
        addresses.append(socket.inet_pton(socket.AF_INET6, '::1'))
        expected.add('::1')
    info = ServiceInfo(
        "_http._tcp.local.",
        "My Service Name._http._tcp.local.",
        addresses=addresses,
        port=1234,
        properties=desc,
    )
    print("   Registering service...")
    r.register_service(info)
    print("   Registration done.")
    print("2. Testing query of service information...")
    print("   Getting ZOE service: %s" % (r.get_service_info("_http._tcp.local.", "ZOE._http._tcp.local.")))
    print("   Query done.")
    print("3. Testing query of own service...")
    queried_info = r.get_service_info("_http._tcp.local.", "My Service Name._http._tcp.local.")
    assert queried_info
    assert set(queried_info.parsed_addresses()) == expected
    print("   Getting self: %s" % (queried_info,))
    print("   Query done.")
    print("4. Testing unregister of service information...")
    r.unregister_service(info)
    print("   Unregister done.")
    r.close()
