"""A pure python implementation of multicast DNS service discovery.

Licensed under LGPL-2.1-or-later; see COPYING for details. This file is
part of a continuously modified work; modification dates are recorded
in the project's git history.
"""

from __future__ import annotations

import asyncio
import contextlib
from collections.abc import Awaitable, Callable
from types import TracebackType  # used in type hints

from ._core import Zeroconf
from ._dns import DNSQuestionType
from ._exceptions import NotRunningException
from ._services import ServiceListener
from ._services.browser import _ServiceBrowserBase
from ._services.info import AsyncServiceInfo, ServiceInfo
from ._services.types import ZeroconfServiceTypes
from ._utils.net import InterfaceChoice, InterfacesType, IPVersion
from .const import _BROWSER_TIME, _MDNS_PORT, _SERVICE_TYPE_ENUMERATION_NAME

__all__ = [
    "AsyncServiceBrowser",
    "AsyncServiceInfo",
    "AsyncZeroconf",
    "AsyncZeroconfServiceTypes",
]


class AsyncServiceBrowser(_ServiceBrowserBase):
    """Event loop browser that fires ServiceListener callbacks as services
    of the requested types appear, change, and disappear."""

    def __init__(
        self,
        zeroconf: Zeroconf,
        type_: str | list,
        handlers: ServiceListener | list[Callable[..., None]] | None = None,
        listener: ServiceListener | None = None,
        addr: str | None = None,
        port: int = _MDNS_PORT,
        delay: int = _BROWSER_TIME,
        question_type: DNSQuestionType | None = None,
    ) -> None:
        super().__init__(zeroconf, type_, handlers, listener, addr, port, delay, question_type)
        self._async_start()

    async def __aenter__(self) -> AsyncServiceBrowser:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool | None:
        await self.async_cancel()
        return None

    async def async_cancel(self) -> None:
        """Cancel the browser."""
        self._async_cancel()


class AsyncZeroconfServiceTypes(ZeroconfServiceTypes):
    """An async version of ZeroconfServiceTypes."""

    @classmethod
    async def async_find(
        cls,
        aiozc: AsyncZeroconf | None = None,
        timeout: int | float = 5,
        interfaces: InterfacesType = InterfaceChoice.All,
        ip_version: IPVersion | None = None,
    ) -> tuple[str, ...]:
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
            local_zc.zeroconf, _SERVICE_TYPE_ENUMERATION_NAME, listener=listener
        )

        # wait for responses
        await asyncio.sleep(timeout)

        await async_browser.async_cancel()

        # close down anything we opened
        if aiozc is None:
            await local_zc.async_close()

        return tuple(sorted(listener.found_services))


class AsyncZeroconf:
    """Awaitable facade over Zeroconf for registration, browsing, and
    resolution; expects a running asyncio event loop."""

    def __init__(
        self,
        interfaces: InterfacesType = InterfaceChoice.All,
        unicast: bool = False,
        ip_version: IPVersion | None = None,
        apple_p2p: bool = False,
        zc: Zeroconf | None = None,
    ) -> None:
        """Create or wrap a Zeroconf instance for use from asyncio.

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
        self.async_browsers: dict[ServiceListener, AsyncServiceBrowser] = {}

    async def __aenter__(self) -> AsyncZeroconf:
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool | None:
        await self.async_close()
        return None

    async def async_add_service_listener(self, type_: str, listener: ServiceListener) -> None:
        """Browse a service type, delivering events to the listener.

        Replaces any browser previously registered for the same listener.
        """
        await self.async_remove_service_listener(listener)
        self.async_browsers[listener] = AsyncServiceBrowser(self.zeroconf, type_, listener)

    async def async_close(self) -> None:
        """Unregister everything and shut the wrapped Zeroconf down."""
        if not self.zeroconf.done:
            with contextlib.suppress(NotRunningException):
                await self.zeroconf.async_wait_for_start(timeout=1.0)
        await self.async_remove_all_service_listeners()
        await self.async_unregister_all_services()
        await self.zeroconf._async_close()  # pylint: disable=protected-access

    async def async_get_service_info(
        self,
        type_: str,
        name: str,
        timeout: int = 3000,
        question_type: DNSQuestionType | None = None,
    ) -> AsyncServiceInfo | None:
        """Look up details for a service on the network.

        Queries for the given fully qualified type and name, waiting up to
        timeout milliseconds, and returns a populated AsyncServiceInfo or
        None when nothing answered in time. question_type forces QM or QU
        questions instead of the automatic choice.
        """
        return await self.zeroconf.async_get_service_info(type_, name, timeout, question_type)

    async def async_register_service(
        self,
        info: ServiceInfo,
        ttl: int | None = None,
        allow_name_change: bool = False,
        cooperating_responders: bool = False,
        strict: bool = True,
    ) -> Awaitable:
        """Announce a service on the network.

        Returns an awaitable that completes once the announcements have
        been sent.
        """
        return await self.zeroconf.async_register_service(
            info, ttl, allow_name_change, cooperating_responders, strict
        )

    async def async_remove_all_service_listeners(self) -> None:
        """Stop and drop every browser started through add_service_listener."""
        await asyncio.gather(
            *(self.async_remove_service_listener(listener) for listener in list(self.async_browsers))
        )

    async def async_remove_service_listener(self, listener: ServiceListener) -> None:
        """Stop and drop the browser registered for the listener, if any."""
        if listener in self.async_browsers:
            await self.async_browsers[listener].async_cancel()
            del self.async_browsers[listener]

    async def async_unregister_all_services(self) -> None:
        """Send goodbye packets for every registered service and drop them all.

        Runs only at shutdown, so unlike the single service calls it
        returns nothing to await separately.
        """
        await self.zeroconf.async_unregister_all_services()

    async def async_unregister_service(self, info: ServiceInfo) -> Awaitable:
        """Withdraw a service, returning an awaitable that completes once the goodbyes are sent."""
        return await self.zeroconf.async_unregister_service(info)

    async def async_update_interfaces(
        self,
        interfaces: InterfacesType | None = None,
        ip_version: IPVersion | None = None,
        apple_p2p: bool | None = None,
    ) -> None:
        """Rescan network interfaces and reconcile the sockets in use.

        Adds sockets for interfaces that appeared, drops sockets for
        interfaces that disappeared, and re-announces existing
        registrations on the resulting senders. ``interfaces``,
        ``ip_version`` and ``apple_p2p`` each default to the construction-time
        value. Raises RuntimeError if apple_p2p is set on a non-Apple platform.
        """
        await self.zeroconf.async_update_interfaces(interfaces, ip_version, apple_p2p)

    async def async_update_service(self, info: ServiceInfo) -> Awaitable:
        """Publish updated records for an already registered service.

        Returns an awaitable that completes once the rebroadcasts finish.
        """
        return await self.zeroconf.async_update_service(info)
