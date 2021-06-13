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
import queue
import threading
from types import TracebackType  # noqa # used in type hints
from typing import Awaitable, Callable, Dict, List, Optional, Type, Union

from ._core import NotifyListener, Zeroconf
from ._dns import DNSOutgoing
from ._exceptions import NonUniqueNameException
from ._utils.aio import wait_condition_or_timeout
from ._utils.net import IPVersion, InterfaceChoice, InterfacesType
from ._utils.time import current_time_millis, millis_to_seconds
from .const import _BROWSER_TIME, _CHECK_TIME, _LISTENER_TIME, _MDNS_PORT, _REGISTER_TIME, _UNREGISTER_TIME
from .services import ServiceInfo, _ServiceBrowserBase, instance_name_from_service_info


def _get_best_available_queue() -> queue.Queue:
    """Create the best available queue type."""
    if hasattr(queue, "SimpleQueue"):
        return queue.SimpleQueue()  # type: ignore  # pylint: disable=all
    return queue.Queue()


class _AsyncSender(threading.Thread):
    """A thread to handle sending DNSOutgoing for asyncio."""

    def __init__(self, zc: 'Zeroconf'):
        """Create the sender thread."""
        super().__init__()
        self.zc = zc
        self.queue = _get_best_available_queue()
        self.start()
        self.name = "AsyncZeroconfSender"

    def send(self, out: DNSOutgoing, addr: Optional[str] = None, port: int = _MDNS_PORT) -> None:
        """Queue a send to be processed by the thread."""
        self.queue.put((out, addr, port))

    def close(self) -> None:
        """Close the instance."""
        self.queue.put(None)
        self.join()

    def run(self) -> None:
        """Runner that processes sends FIFO."""
        while True:
            event = self.queue.get()
            if event is None:
                return
            self.zc.send(*event)


class AsyncNotifyListener(NotifyListener):
    """A NotifyListener that async code can use to wait for events."""

    def __init__(self, aiozc: 'AsyncZeroconf') -> None:
        """Create an event for async listeners to wait for."""
        self.aiozc = aiozc
        self.loop = asyncio.get_event_loop()

    def notify_all(self) -> None:
        """Schedule an async_notify_all."""
        self.loop.call_soon_threadsafe(asyncio.ensure_future, self._async_notify_all())

    async def _async_notify_all(self) -> None:
        """Notify all async listeners."""
        async with self.aiozc.condition:
            self.aiozc.condition.notify_all()


class AsyncServiceListener:
    def add_service(self, aiozc: 'AsyncZeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()

    def remove_service(self, aiozc: 'AsyncZeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()

    def update_service(self, aiozc: 'AsyncZeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()


class AsyncServiceInfo(ServiceInfo):
    """An async version of ServiceInfo."""

    async def async_request(self, aiozc: 'AsyncZeroconf', timeout: float) -> bool:
        """Returns true if the service could be discovered on the
        network, and updates this object with details discovered.
        """
        if self.load_from_cache(aiozc.zeroconf):
            return True

        now = current_time_millis()
        delay = _LISTENER_TIME
        next_ = now
        last = now + timeout
        try:
            aiozc.zeroconf.add_listener(self, None)
            while not self._is_complete:
                if last <= now:
                    return False
                if next_ <= now:
                    out = self.generate_request_query(aiozc.zeroconf, now)
                    if not out.questions:
                        return self.load_from_cache(aiozc.zeroconf)
                    aiozc.sender.send(out)
                    next_ = now + delay
                    delay *= 2

                await aiozc.async_wait(min(next_, last) - now)
                now = current_time_millis()
        finally:
            aiozc.zeroconf.remove_listener(self)

        return True


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
        self._browser_task = asyncio.ensure_future(self.async_run())

    async def async_cancel(self) -> None:
        """Cancel the browser."""
        self.cancel()
        self._browser_task.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await self._browser_task

    async def async_run(self) -> None:
        """Run the browser task."""
        self.run()
        while True:
            timeout = self._seconds_to_wait()
            if timeout:
                async with self.aiozc.condition:
                    # We must check again while holding the condition
                    # in case the other thread has added to _handlers_to_call
                    # between when we checked above when we were not
                    # holding the condition
                    if not self._handlers_to_call:
                        await wait_condition_or_timeout(self.aiozc.condition, timeout)

            out = self.generate_ready_queries()
            if out:
                self.aiozc.sender.send(out, addr=self.addr, port=self.port)

            if not self._handlers_to_call:
                continue

            (name_type, state_change) = self._handlers_to_call.popitem(False)
            self._service_state_changed.fire(
                zeroconf=self.aiozc,
                service_type=name_type[1],
                name=name_type[0],
                state_change=state_change,
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
        self.loop = asyncio.get_event_loop()
        self.async_notify = AsyncNotifyListener(self)
        self.zeroconf.add_notify_listener(self.async_notify)
        self.async_browsers: Dict[AsyncServiceListener, AsyncServiceBrowser] = {}
        self.sender = _AsyncSender(self.zeroconf)
        self.condition = asyncio.Condition()

    async def _async_broadcast_service(self, info: ServiceInfo, interval: int, ttl: Optional[int]) -> None:
        """Send a broadcasts to announce a service at intervals."""
        for i in range(3):
            if i != 0:
                await asyncio.sleep(millis_to_seconds(interval))
            self.sender.send(self.zeroconf.generate_service_broadcast(info, ttl))

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
        await self.async_check_service(info, cooperating_responders)
        self.zeroconf.registry.add(info)
        return asyncio.ensure_future(self._async_broadcast_service(info, _REGISTER_TIME, None))

    async def async_check_service(self, info: ServiceInfo, cooperating_responders: bool = False) -> None:
        """Checks the network for a unique service name."""
        instance_name_from_service_info(info)
        if cooperating_responders:
            return
        self._raise_on_name_conflict(info)
        for i in range(3):
            if i != 0:
                await asyncio.sleep(millis_to_seconds(_CHECK_TIME))
            self.sender.send(self.zeroconf.generate_service_query(info))
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

    def _close(self) -> None:
        """Shutdown zeroconf and the sender."""
        self.sender.close()
        self.zeroconf.remove_notify_listener(self.async_notify)
        self.zeroconf.close()

    async def async_close(self) -> None:
        """Ends the background threads, and prevent this instance from
        servicing further queries."""
        await self.async_remove_all_service_listeners()
        await self.loop.run_in_executor(None, self._close)

    async def async_get_service_info(
        self, type_: str, name: str, timeout: int = 3000
    ) -> Optional[AsyncServiceInfo]:
        """Returns network's service information for a particular
        name and type, or None if no service matches by the timeout,
        which defaults to 3 seconds."""
        info = AsyncServiceInfo(type_, name)
        if await info.async_request(self, timeout):
            return info
        return None

    async def async_wait(self, timeout: float) -> None:
        """Calling task waits for a given number of milliseconds or until notified."""
        async with self.condition:
            await wait_condition_or_timeout(self.condition, millis_to_seconds(timeout))

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
