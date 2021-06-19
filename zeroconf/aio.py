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
import contextlib
from types import TracebackType  # noqa # used in type hints
from typing import Awaitable, Callable, Dict, List, Optional, Tuple, Type, Union, cast

from ._core import Zeroconf
from ._exceptions import NonUniqueNameException
from ._services.browser import _ServiceBrowserBase
from ._services.info import ServiceInfo, instance_name_from_service_info
from ._services.types import ZeroconfServiceTypes
from ._utils.net import IPVersion, InterfaceChoice, InterfacesType
from ._utils.time import millis_to_seconds
from .const import (
    _BROWSER_TIME,
    _CHECK_TIME,
    _MDNS_PORT,
    _REGISTER_TIME,
    _SERVICE_TYPE_ENUMERATION_NAME,
    _UNREGISTER_TIME,
)


__all__ = [
    "AsyncZeroconf",
    "AsyncServiceInfo",
    "AsyncServiceBrowser",
    "AsyncServiceListener",
    "AsyncZeroconfServiceTypes",
]


class AsyncServiceListener:
    def add_service(self, aiozc: 'AsyncZeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()

    def remove_service(self, aiozc: 'AsyncZeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()

    def update_service(self, aiozc: 'AsyncZeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()


class AsyncServiceInfo(ServiceInfo):
    """An async version of ServiceInfo."""


class AsyncServiceBrowser(_ServiceBrowserBase):
    """Used to browse for a service of a specific type.

    The listener object will have its add_service() and
    remove_service() methods called when this browser
    discovers changes in the services availability."""

    def __init__(
        self,
        aiozc: 'AsyncZeroconf',
        type_: Union[str, list],
        handlers: Optional[Union[AsyncServiceListener, List[Callable[..., None]]]] = None,
        listener: Optional[AsyncServiceListener] = None,
        addr: Optional[str] = None,
        port: int = _MDNS_PORT,
        delay: int = _BROWSER_TIME,
    ) -> None:
        self.aiozc = aiozc
        super().__init__(aiozc.zeroconf, type_, handlers, listener, addr, port, delay)  # type: ignore
        self._browser_task = cast(asyncio.Task, asyncio.ensure_future(self.async_browser_task()))

    async def async_cancel(self) -> None:
        """Cancel the browser."""
        await self._async_cancel_browser()
        super().cancel()


class AsyncZeroconfServiceTypes(ZeroconfServiceTypes):
    """An async version of ZeroconfServiceTypes."""

    @classmethod
    async def async_find(
        cls,
        aiozc: Optional['AsyncZeroconf'] = None,
        timeout: Union[int, float] = 5,
        interfaces: InterfacesType = InterfaceChoice.All,
        ip_version: Optional[IPVersion] = None,
    ) -> Tuple[str, ...]:
        """
        Return all of the advertised services on any local networks.

        :param aiozc: AsyncZeroconf() instance.  Pass in if already have an
                instance running or if non-default interfaces are needed
        :param timeout: seconds to wait for any responses
        :param interfaces: interfaces to listen on.
        :param ip_version: IP protocol version to use.
        :return: tuple of service type strings
        """
        local_zc = aiozc or AsyncZeroconf(interfaces=interfaces, ip_version=ip_version)
        listener = cls()
        async_browser = AsyncServiceBrowser(
            local_zc, _SERVICE_TYPE_ENUMERATION_NAME, listener=listener  # type: ignore
        )

        # wait for responses
        await asyncio.sleep(timeout)

        await async_browser.async_cancel()

        # close down anything we opened
        if aiozc is None:
            await local_zc.async_close()

        return tuple(sorted(listener.found_services))


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
        zc: Optional[Zeroconf] = None,
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
        self.zeroconf = zc or Zeroconf(
            interfaces=interfaces,
            unicast=unicast,
            ip_version=ip_version,
            apple_p2p=apple_p2p,
        )
        self.async_browsers: Dict[AsyncServiceListener, AsyncServiceBrowser] = {}

    async def _async_broadcast_service(self, info: ServiceInfo, interval: int, ttl: Optional[int]) -> None:
        """Send a broadcasts to announce a service at intervals."""
        for i in range(3):
            if i != 0:
                await asyncio.sleep(millis_to_seconds(interval))
            self.zeroconf.async_send(self.zeroconf.generate_service_broadcast(info, ttl))

    async def async_register_service(
        self,
        info: ServiceInfo,
        cooperating_responders: bool = False,
    ) -> Awaitable:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service.  The name of the service may be changed if needed to make
        it unique on the network. Additionally multiple cooperating responders
        can register the same service on the network for resilience
        (if you want this behavior set `cooperating_responders` to `True`).

        The service will be broadcast in a task. This task is returned
        and therefore can be awaited if necessary.
        """
        await self.zeroconf.async_wait_for_start()
        await self.async_check_service(info, cooperating_responders)
        self.zeroconf.registry.add(info)
        return asyncio.ensure_future(self._async_broadcast_service(info, _REGISTER_TIME, None))

    async def async_unregister_all_services(self) -> None:
        """Unregister all registered services.

        Unlike async_register_service and async_unregister_service, this
        method does not return a future and is always expected to be
        awaited since its only called at shutdown.
        """
        out = self.zeroconf.generate_unregister_all_services()
        if not out:
            return
        for i in range(3):
            if i != 0:
                await asyncio.sleep(millis_to_seconds(_UNREGISTER_TIME))
            self.zeroconf.async_send(out)

    async def async_check_service(self, info: ServiceInfo, cooperating_responders: bool = False) -> None:
        """Checks the network for a unique service name."""
        instance_name_from_service_info(info)
        if cooperating_responders:
            return
        self._raise_on_name_conflict(info)
        for i in range(3):
            if i != 0:
                await asyncio.sleep(millis_to_seconds(_CHECK_TIME))
            self.zeroconf.async_send(self.zeroconf.generate_service_query(info))
            self._raise_on_name_conflict(info)

    def _raise_on_name_conflict(self, info: ServiceInfo) -> None:
        """Raise NonUniqueNameException if the ServiceInfo has a conflict."""
        if self.zeroconf.cache.current_entry_with_name_and_alias(info.type, info.name):
            raise NonUniqueNameException

    async def async_unregister_service(self, info: ServiceInfo) -> Awaitable:
        """Unregister a service.

        The service will be broadcast in a task. This task is returned
        and therefore can be awaited if necessary.
        """
        self.zeroconf.registry.remove(info)
        return asyncio.ensure_future(self._async_broadcast_service(info, _UNREGISTER_TIME, 0))

    async def async_update_service(self, info: ServiceInfo) -> Awaitable:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service.

        The service will be broadcast in a task. This task is returned
        and therefore can be awaited if necessary.
        """
        self.zeroconf.registry.update(info)
        return asyncio.ensure_future(self._async_broadcast_service(info, _REGISTER_TIME, None))

    async def async_close(self) -> None:
        """Ends the background threads, and prevent this instance from
        servicing further queries."""
        with contextlib.suppress(asyncio.TimeoutError):
            await asyncio.wait_for(self.zeroconf.async_wait_for_start(), timeout=1)
        await self.async_remove_all_service_listeners()
        await self.async_unregister_all_services()
        await self.zeroconf._async_close()  # pylint: disable=protected-access

    async def async_get_service_info(
        self, type_: str, name: str, timeout: int = 3000
    ) -> Optional[AsyncServiceInfo]:
        """Returns network's service information for a particular
        name and type, or None if no service matches by the timeout,
        which defaults to 3 seconds."""
        info = AsyncServiceInfo(type_, name)
        if await info.async_request(self.zeroconf, timeout):
            return info
        return None

    async def async_add_service_listener(self, type_: str, listener: AsyncServiceListener) -> None:
        """Adds a listener for a particular service type.  This object
        will then have its add_service and remove_service methods called when
        services of that type become available and unavailable."""
        await self.async_remove_service_listener(listener)
        self.async_browsers[listener] = AsyncServiceBrowser(self, type_, listener)

    async def async_remove_service_listener(self, listener: AsyncServiceListener) -> None:
        """Removes a listener from the set that is currently listening."""
        if listener in self.async_browsers:
            await self.async_browsers[listener].async_cancel()
            del self.async_browsers[listener]

    async def async_remove_all_service_listeners(self) -> None:
        """Removes a listener from the set that is currently listening."""
        await asyncio.gather(
            *[self.async_remove_service_listener(listener) for listener in list(self.async_browsers)]
        )

    async def __aenter__(self) -> 'AsyncZeroconf':
        return self

    async def __aexit__(
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Optional[bool]:
        await self.async_close()
        return None
