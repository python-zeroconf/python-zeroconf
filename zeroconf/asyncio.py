""" Multicast DNS Service Discovery for Python, v0.14-wmcbrine
    Copyright 2003 Paul Scott-Murphy, 2014 William McBrine

    This module provides a framework for the use of DNS Service Discovery
    using IP multicast.

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
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
    USA
"""
import asyncio
from typing import Optional

from . import (
    IPVersion,
    InterfaceChoice,
    InterfacesType,
    ServiceInfo,
    Zeroconf,
    _REGISTER_TIME,
    _UNREGISTER_TIME,
)


class AsyncZeroconf:
    """Implementation of Zeroconf Multicast DNS Service Discovery

    Supports registration, unregistration, queries and browsing.

    The async version is currently a wrapper around the sync version
    with I/O being done in the executor for backwards compatibility.
    """

    def __init__(
        self,
        interfaces: InterfacesType = InterfaceChoice.All,
        unicast: bool = False,
        ip_version: Optional[IPVersion] = None,
        apple_p2p: bool = False,
    ) -> None:
        """Creates an instance of the Zeroconf class, establishing
        multicast communications, listening and reaping threads.

        :param interfaces: :class:`InterfaceChoice` or a list of IP addresses
            (IPv4 and IPv6) and interface indexes (IPv6 only).

            IPv6 notes for non-POSIX systems:
            * `InterfaceChoice.All` is an alias for `InterfaceChoice.Default`
              on Python versions before 3.8.

            Also listening on loopback (``::1``) doesn't work, use a real address.
        :param ip_version: IP versions to support. If `choice` is a list, the default is detected
            from it. Otherwise defaults to V4 only for backward compatibility.
        :param apple_p2p: use AWDL interface (only macOS)
        """
        self.zeroconf = Zeroconf(
            interfaces=interfaces,
            unicast=unicast,
            ip_version=ip_version,
            apple_p2p=apple_p2p,
        )
        self.loop = asyncio.get_event_loop()

    async def _async_broadcast_service(self, info: ServiceInfo, interval: int, ttl: Optional[int]) -> None:
        """Send a broadcasts to announce a service at intervals."""
        for i in range(3):
            if i != 0:
                await asyncio.sleep(interval / 1000)
            await self.loop.run_in_executor(None, self.zeroconf.send_service_broadcast, info, ttl)

    async def async_register_service(
        self,
        info: ServiceInfo,
        ttl: Optional[int] = None,
        allow_name_change: bool = False,
        cooperating_responders: bool = False,
        broadcast_service: bool = True,
    ) -> None:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service.  The name of the service may be changed if needed to make
        it unique on the network. Additionally multiple cooperating responders
        can register the same service on the network for resilience
        (if you want this behavior set `cooperating_responders` to `True`).

        By default, the service will be announced if broadcast_service is set to True.
        The service will be broadcast in a task.
        """
        await self.loop.run_in_executor(
            None, self.zeroconf.register_service, info, ttl, allow_name_change, cooperating_responders, False
        )
        if broadcast_service:
            asyncio.ensure_future(self._async_broadcast_service(info, _REGISTER_TIME, ttl))

    async def async_unregister_service(self, info: ServiceInfo, broadcast_service: bool = True) -> None:
        """Unregister a service.

        By default, the service will be announced if broadcast_service is set to True.
        The service will be broadcast in a task.
        """
        await self.loop.run_in_executor(None, self.zeroconf.unregister_service, info, False)
        if broadcast_service:
            asyncio.ensure_future(self._async_broadcast_service(info, _UNREGISTER_TIME, 0))

    async def async_update_service(self, info: ServiceInfo, broadcast_service: bool = True) -> None:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service.

        By default, the service will be announced if broadcast_service is set to True.
        The service will be broadcast in a task.
        """
        await self.loop.run_in_executor(None, self.zeroconf.update_service, info, False)
        if broadcast_service:
            asyncio.ensure_future(self._async_broadcast_service(info, _REGISTER_TIME, None))

    async def async_close(self) -> None:
        """Ends the background threads, and prevent this instance from
        servicing further queries."""
        await self.loop.run_in_executor(None, self.zeroconf.close)
