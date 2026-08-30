"""A pure python implementation of multicast DNS service discovery.

Licensed under LGPL-2.1-or-later; see COPYING for details. This file is
part of a continuously modified work; modification dates are recorded
in the project's git history.
"""

from __future__ import annotations

import time

from .._core import Zeroconf
from .._services import ServiceListener
from .._utils.net import InterfaceChoice, InterfacesType, IPVersion
from ..const import _SERVICE_TYPE_ENUMERATION_NAME
from .browser import ServiceBrowser


class ZeroconfServiceTypes(ServiceListener):
    """
    Return all of the advertised services on any local networks
    """

    def __init__(self) -> None:
        """Keep track of found services in a set."""
        self.found_services: set[str] = set()

    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Service added."""
        self.found_services.add(name)

    @classmethod
    def find(
        cls,
        zc: Zeroconf | None = None,
        timeout: int | float = 5,
        interfaces: InterfacesType = InterfaceChoice.All,
        ip_version: IPVersion | None = None,
    ) -> tuple[str, ...]:
        """
        Return all of the advertised services on any local networks.

        :param zc: Zeroconf() instance.  Pass in if already have an
                instance running or if non-default interfaces are needed
        :param timeout: seconds to wait for any responses
        :param interfaces: interfaces to listen on.
        :param ip_version: IP protocol version to use.
        :return: tuple of service type strings
        """
        local_zc = zc or Zeroconf(interfaces=interfaces, ip_version=ip_version)
        listener = cls()
        browser = ServiceBrowser(local_zc, _SERVICE_TYPE_ENUMERATION_NAME, listener=listener)

        # wait for responses
        time.sleep(timeout)

        browser.cancel()

        # close down anything we opened
        if zc is None:
            local_zc.close()

        return tuple(sorted(listener.found_services))

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Service removed."""

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        """Service updated."""
