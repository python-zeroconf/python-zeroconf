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
    NonUniqueNameException,
    ServiceInfo,
    Zeroconf,
    _CHECK_TIME,
    _REGISTER_TIME,
    _UNREGISTER_TIME,
    instance_name_from_service_info,
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
        cooperating_responders: bool = False,
    ) -> None:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service.  The name of the service may be changed if needed to make
        it unique on the network. Additionally multiple cooperating responders
        can register the same service on the network for resilience
        (if you want this behavior set `cooperating_responders` to `True`).

        The service will be broadcast in a task.
        """
        await self.async_check_service(info, cooperating_responders)
        await self.loop.run_in_executor(None, self.zeroconf.registry.add, info)
        asyncio.ensure_future(self._async_broadcast_service(info, _REGISTER_TIME, None))

    async def async_check_service(self, info: ServiceInfo, cooperating_responders: bool = False) -> None:
        """Checks the network for a unique service name."""
        instance_name_from_service_info(info)
        if cooperating_responders:
            return
        for i in range(3):
            # check for a name conflict
            if self.zeroconf.cache.current_entry_with_name_and_alias(info.type, info.name):
                raise NonUniqueNameException
            if i != 0:
                await asyncio.sleep(_CHECK_TIME / 1000)
            await self.loop.run_in_executor(None, self.zeroconf.send_service_query, info)

    async def async_unregister_service(self, info: ServiceInfo) -> None:
        """Unregister a service.

        The service will be broadcast in a task.
        """
        await self.loop.run_in_executor(None, self.zeroconf.registry.remove, info)
        asyncio.ensure_future(self._async_broadcast_service(info, _UNREGISTER_TIME, 0))

    async def async_update_service(self, info: ServiceInfo) -> None:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service.

        The service will be broadcast in a task.
        """
        await self.loop.run_in_executor(None, self.zeroconf.registry.update, info)
        asyncio.ensure_future(self._async_broadcast_service(info, _REGISTER_TIME, None))

    async def async_close(self) -> None:
        """Ends the background threads, and prevent this instance from
        servicing further queries."""
        await self.loop.run_in_executor(None, self.zeroconf.close)
