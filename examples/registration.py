#!/usr/bin/env python3

""" Example of announcing a service (in this case, a fake HTTP server) """

import argparse
import logging
import socket
from time import sleep

from zeroconf import IPVersion, ServiceInfo, Zeroconf

if __name__ == '__main__':
    logging.basicConfig(level=logging.DEBUG)

    parser = argparse.ArgumentParser()
    parser.add_argument('--debug', action='store_true')
    version_group = parser.add_mutually_exclusive_group()
    version_group.add_argument('--v6', action='store_true')
    version_group.add_argument('--v6-only', action='store_true')
    args = parser.parse_args()

    if args.debug:
        logging.getLogger('zeroconf').setLevel(logging.DEBUG)
    if args.v6:
        ip_version = IPVersion.All
    elif args.v6_only:
        ip_version = IPVersion.V6Only
    else:
        ip_version = IPVersion.V4Only

    desc = {'dummy': 'abcd', 'thread-test': 'a49'}

    infos = []
    for i in range(1,6):
        infos.append(
            ServiceInfo(
                "service-test-1._infra-test._udp.local.",
                f"service-test-{1}._infra-test._udp.local.",
                addresses=[socket.inet_pton(socket.AF_INET6,"fe80::6770:70:d014:327"), socket.inet_pton(socket.AF_INET6,"fd40:591:1750:102e:4f65:7721:b7e8:8419")],
                port=55550+i,
                properties=desc,
                server="host-test-eth.local.",
            )
        )

    zeroconf = Zeroconf(ip_version=ip_version)
    print("Registration of a service, press Ctrl-C to exit...")
    zeroconf.register_service(infos)
    try:
        while True:
            sleep(0.1)
    except KeyboardInterrupt:
        pass
    finally:
        print("Unregistering...")
        zeroconf.unregister_service(infos)
        zeroconf.close()
