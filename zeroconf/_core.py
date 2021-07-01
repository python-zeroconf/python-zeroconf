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
import concurrent.futures
import contextlib
import itertools
import random
import socket
import sys
import threading
from types import TracebackType  # noqa # used in type hints
from typing import Dict, List, Optional, Tuple, Type, Union, cast

from ._cache import DNSCache
from ._dns import DNSQuestion, DNSQuestionType
from ._exceptions import NonUniqueNameException
from ._handlers import QueryHandler, RecordManager
from ._history import QuestionHistory
from ._logger import QuietLogger, log
from ._protocol import DNSIncoming, DNSOutgoing
from ._services import ServiceListener
from ._services.browser import ServiceBrowser
from ._services.info import ServiceInfo, instance_name_from_service_info
from ._services.registry import ServiceRegistry
from ._updates import RecordUpdate, RecordUpdateListener
from ._utils.asyncio import get_running_loop, shutdown_loop, wait_event_or_timeout
from ._utils.name import service_type_name
from ._utils.net import (
    IPVersion,
    InterfaceChoice,
    InterfacesType,
    autodetect_ip_version,
    can_send_to,
    create_sockets,
)
from ._utils.time import current_time_millis, millis_to_seconds
from .const import (
    _CACHE_CLEANUP_INTERVAL,
    _CHECK_TIME,
    _CLASS_IN,
    _CLASS_UNIQUE,
    _FLAGS_AA,
    _FLAGS_QR_QUERY,
    _FLAGS_QR_RESPONSE,
    _LOADED_SYSTEM_TIMEOUT,
    _MAX_MSG_ABSOLUTE,
    _MDNS_ADDR,
    _MDNS_ADDR6,
    _MDNS_PORT,
    _REGISTER_TIME,
    _TYPE_PTR,
    _UNREGISTER_TIME,
)

_TC_DELAY_RANDOM_INTERVAL = (400, 500)
_CLOSE_TIMEOUT = 3


class AsyncEngine:
    """An engine wraps sockets in the event loop."""

    def __init__(
        self,
        zeroconf: 'Zeroconf',
        listen_socket: Optional[socket.socket],
        respond_sockets: List[socket.socket],
    ) -> None:
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self.zc = zeroconf
        self.protocols: List[AsyncListener] = []
        self.readers: List[asyncio.DatagramTransport] = []
        self.senders: List[asyncio.DatagramTransport] = []
        self._listen_socket = listen_socket
        self._respond_sockets = respond_sockets
        self._cache_cleanup_task: Optional[asyncio.Task] = None
        self._running_event: Optional[asyncio.Event] = None

    def setup(self, loop: asyncio.AbstractEventLoop, loop_thread_ready: Optional[threading.Event]) -> None:
        """Set up the instance."""
        self.loop = loop
        self._running_event = asyncio.Event()
        self.loop.create_task(self._async_setup(loop_thread_ready))

    async def _async_setup(self, loop_thread_ready: Optional[threading.Event]) -> None:
        """Set up the instance."""
        assert self.loop is not None
        await self._async_create_endpoints()
        self._cache_cleanup_task = self.loop.create_task(self._async_cache_cleanup())
        assert self._running_event is not None
        self._running_event.set()
        if loop_thread_ready:
            loop_thread_ready.set()

    async def async_wait_for_start(self) -> None:
        """Wait for start up."""
        assert self._running_event is not None
        await self._running_event.wait()

    async def _async_create_endpoints(self) -> None:
        """Create endpoints to send and receive."""
        assert self.loop is not None
        loop = self.loop
        reader_sockets = []
        sender_sockets = []
        if self._listen_socket:
            reader_sockets.append(self._listen_socket)
        for s in self._respond_sockets:
            if s not in reader_sockets:
                reader_sockets.append(s)
            sender_sockets.append(s)

        for s in reader_sockets:
            transport, protocol = await loop.create_datagram_endpoint(lambda: AsyncListener(self.zc), sock=s)
            self.protocols.append(cast(AsyncListener, protocol))
            self.readers.append(cast(asyncio.DatagramTransport, transport))
            if s in sender_sockets:
                self.senders.append(cast(asyncio.DatagramTransport, transport))

    async def _async_cache_cleanup(self) -> None:
        """Periodic cache cleanup."""
        while not self.zc.done:
            now = current_time_millis()
            self.zc.question_history.async_expire(now)
            self.zc.record_manager.async_updates(
                now, [RecordUpdate(record, None) for record in self.zc.cache.async_expire(now)]
            )
            self.zc.record_manager.async_updates_complete()
            await asyncio.sleep(millis_to_seconds(_CACHE_CLEANUP_INTERVAL))

    async def _async_close(self) -> None:
        """Cancel and wait for the cleanup task to finish."""
        self._async_shutdown()
        if self._cache_cleanup_task:
            self._cache_cleanup_task.cancel()
            with contextlib.suppress(asyncio.CancelledError):
                await self._cache_cleanup_task
            self._cache_cleanup_task = None
        await asyncio.sleep(0)  # flush out any call soons

    def _async_shutdown(self) -> None:
        """Shutdown transports and sockets."""
        for transport in itertools.chain(self.senders, self.readers):
            transport.close()
        for s in self._respond_sockets:
            s.close()

    def close(self) -> None:
        """Close from sync context."""
        assert self.loop is not None
        # Guard against Zeroconf.close() being called from the eventloop
        if get_running_loop() == self.loop:
            self._async_shutdown()
            return
        if not self.loop.is_running():
            return
        asyncio.run_coroutine_threadsafe(self._async_close(), self.loop).result(
            _CLOSE_TIMEOUT + _LOADED_SYSTEM_TIMEOUT
        )


class AsyncListener(asyncio.Protocol, QuietLogger):

    """A Listener is used by this module to listen on the multicast
    group to which DNS messages are sent, allowing the implementation
    to cache information as it arrives.

    It requires registration with an Engine object in order to have
    the read() method called when a socket is available for reading."""

    def __init__(self, zc: 'Zeroconf') -> None:
        self.zc = zc
        self.data: Optional[bytes] = None
        self.last_time: float = 0
        self.transport: Optional[asyncio.DatagramTransport] = None

        self._deferred: Dict[str, List[DNSIncoming]] = {}
        self._timers: Dict[str, asyncio.TimerHandle] = {}

        super().__init__()

    def suppress_duplicate_packet(self, data: bytes, now: float) -> bool:
        """Suppress duplicate packet if the last one was the same in the last second."""
        if self.data == data and (now - 1000) < self.last_time:
            return True
        self.data = data
        self.last_time = now
        return False

    def datagram_received(
        self, data: bytes, addrs: Union[Tuple[str, int], Tuple[str, int, int, int]]
    ) -> None:
        assert self.transport is not None
        v6_flow_scope: Union[Tuple[()], Tuple[int, int]] = ()
        if len(addrs) == 2:
            # https://github.com/python/mypy/issues/1178
            addr, port = addrs  # type: ignore
            scope = None
        else:
            # https://github.com/python/mypy/issues/1178
            addr, port, flow, scope = addrs  # type: ignore
            log.debug('IPv6 scope_id %d associated to the receiving interface', scope)
            v6_flow_scope = (flow, scope)

        now = current_time_millis()
        if self.suppress_duplicate_packet(data, now):
            # Guard against duplicate packets
            log.debug(
                'Ignoring duplicate message received from %r:%r (socket %d) (%d bytes) as [%r]',
                addr,
                port,
                self.transport.get_extra_info('socket').fileno(),
                len(data),
                data,
            )
            return

        if len(data) > _MAX_MSG_ABSOLUTE:
            # Guard against oversized packets to ensure bad implementations cannot overwhelm
            # the system.
            log.debug(
                "Discarding incoming packet with length %s, which is larger "
                "than the absolute maximum size of %s",
                len(data),
                _MAX_MSG_ABSOLUTE,
            )
            return

        msg = DNSIncoming(data, scope, now)
        if msg.valid:
            log.debug(
                'Received from %r:%r (socket %d): %r (%d bytes) as [%r]',
                addr,
                port,
                self.transport.get_extra_info('socket').fileno(),
                msg,
                len(data),
                data,
            )
        else:
            log.debug(
                'Received from %r:%r (socket %d): (%d bytes) [%r]',
                addr,
                port,
                self.transport.get_extra_info('socket').fileno(),
                len(data),
                data,
            )
            return

        if not msg.is_query():
            self.zc.handle_response(msg)
            return

        self.handle_query_or_defer(msg, addr, port, v6_flow_scope)

    def handle_query_or_defer(
        self, msg: DNSIncoming, addr: str, port: int, v6_flow_scope: Union[Tuple[()], Tuple[int, int]] = ()
    ) -> None:
        """Deal with incoming query packets.  Provides a response if
        possible."""
        if not msg.truncated:
            self._respond_query(msg, addr, port, v6_flow_scope)
            return

        deferred = self._deferred.setdefault(addr, [])
        # If we get the same packet we ignore it
        for incoming in reversed(deferred):
            if incoming.data == msg.data:
                return
        deferred.append(msg)
        delay = millis_to_seconds(random.randint(*_TC_DELAY_RANDOM_INTERVAL))
        assert self.zc.loop is not None
        self._cancel_any_timers_for_addr(addr)
        self._timers[addr] = self.zc.loop.call_later(
            delay, self._respond_query, None, addr, port, v6_flow_scope
        )

    def _cancel_any_timers_for_addr(self, addr: str) -> None:
        """Cancel any future truncated packet timers for the address."""
        if addr in self._timers:
            self._timers.pop(addr).cancel()

    def _respond_query(
        self,
        msg: Optional[DNSIncoming],
        addr: str,
        port: int,
        v6_flow_scope: Union[Tuple[()], Tuple[int, int]] = (),
    ) -> None:
        """Respond to a query and reassemble any truncated deferred packets."""
        self._cancel_any_timers_for_addr(addr)
        packets = self._deferred.pop(addr, [])
        if msg:
            packets.append(msg)

        self.zc.handle_assembled_query(packets, addr, port, v6_flow_scope)

    def error_received(self, exc: Exception) -> None:
        """Likely socket closed or IPv6."""
        assert self.transport is not None
        self.log_warning_once(
            'Error with socket %d: %s', self.transport.get_extra_info('socket').fileno(), exc
        )

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        self.transport = cast(asyncio.DatagramTransport, transport)


class Zeroconf(QuietLogger):

    """Implementation of Zeroconf Multicast DNS Service Discovery

    Supports registration, unregistration, queries and browsing.
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
        if ip_version is None:
            ip_version = autodetect_ip_version(interfaces)

        # hook for threads
        self._GLOBAL_DONE = False

        if apple_p2p and sys.platform != 'darwin':
            raise RuntimeError('Option `apple_p2p` is not supported on non-Apple platforms.')

        listen_socket, respond_sockets = create_sockets(interfaces, unicast, ip_version, apple_p2p=apple_p2p)
        log.debug('Listen socket %s, respond sockets %s', listen_socket, respond_sockets)

        self.engine = AsyncEngine(self, listen_socket, respond_sockets)

        self.browsers: Dict[ServiceListener, ServiceBrowser] = {}
        self.registry = ServiceRegistry()
        self.cache = DNSCache()
        self.question_history = QuestionHistory()
        self.query_handler = QueryHandler(self.registry, self.cache, self.question_history)
        self.record_manager = RecordManager(self)

        self.notify_event: Optional[asyncio.Event] = None
        self.loop: Optional[asyncio.AbstractEventLoop] = None
        self._loop_thread: Optional[threading.Thread] = None

        self.start()

    def start(self) -> None:
        """Start Zeroconf."""
        self.loop = get_running_loop()
        if self.loop:
            self.notify_event = asyncio.Event()
            self.engine.setup(self.loop, None)
            return
        self._start_thread()

    def _start_thread(self) -> None:
        """Start a thread with a running event loop."""
        loop_thread_ready = threading.Event()

        def _run_loop() -> None:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.notify_event = asyncio.Event()
            self.engine.setup(self.loop, loop_thread_ready)
            self.loop.run_forever()

        self._loop_thread = threading.Thread(target=_run_loop, daemon=True)
        self._loop_thread.start()
        loop_thread_ready.wait()

    async def async_wait_for_start(self) -> None:
        """Wait for start up."""
        await self.engine.async_wait_for_start()

    @property
    def done(self) -> bool:
        return self._GLOBAL_DONE

    @property
    def listeners(self) -> List[RecordUpdateListener]:
        return self.record_manager.listeners

    def wait(self, timeout: float) -> None:
        """Calling task waits for a given number of milliseconds or until notified."""
        assert self.loop is not None
        with contextlib.suppress(concurrent.futures.TimeoutError):
            asyncio.run_coroutine_threadsafe(self.async_wait(timeout), self.loop).result(
                millis_to_seconds(timeout)
            )

    async def async_wait(self, timeout: float) -> None:
        """Calling task waits for a given number of milliseconds or until notified."""
        assert self.notify_event is not None
        await wait_event_or_timeout(self.notify_event, timeout=millis_to_seconds(timeout))

    def notify_all(self) -> None:
        """Notifies all waiting threads and notify listeners."""
        assert self.loop is not None
        self.loop.call_soon_threadsafe(self.async_notify_all)

    def async_notify_all(self) -> None:
        """Schedule an async_notify_all."""
        assert self.notify_event is not None
        self.notify_event.set()
        self.notify_event.clear()

    def get_service_info(
        self, type_: str, name: str, timeout: int = 3000, question_type: Optional[DNSQuestionType] = None
    ) -> Optional[ServiceInfo]:
        """Returns network's service information for a particular
        name and type, or None if no service matches by the timeout,
        which defaults to 3 seconds."""
        info = ServiceInfo(type_, name)
        if info.request(self, timeout, question_type):
            return info
        return None

    def add_service_listener(self, type_: str, listener: ServiceListener) -> None:
        """Adds a listener for a particular service type.  This object
        will then have its add_service and remove_service methods called when
        services of that type become available and unavailable."""
        self.remove_service_listener(listener)
        self.browsers[listener] = ServiceBrowser(self, type_, listener)

    def remove_service_listener(self, listener: ServiceListener) -> None:
        """Removes a listener from the set that is currently listening."""
        if listener in self.browsers:
            self.browsers[listener].cancel()
            del self.browsers[listener]

    def remove_all_service_listeners(self) -> None:
        """Removes a listener from the set that is currently listening."""
        for listener in list(self.browsers):
            self.remove_service_listener(listener)

    def register_service(
        self,
        info: ServiceInfo,
        ttl: Optional[int] = None,
        allow_name_change: bool = False,
        cooperating_responders: bool = False,
    ) -> None:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service.  The name of the service may be changed if needed to make
        it unique on the network. Additionally multiple cooperating responders
        can register the same service on the network for resilience
        (if you want this behavior set `cooperating_responders` to `True`)."""
        if ttl is not None:
            # ttl argument is used to maintain backward compatibility
            # Setting TTLs via ServiceInfo is preferred
            info.host_ttl = ttl
            info.other_ttl = ttl
        self.check_service(info, allow_name_change, cooperating_responders)
        self.registry.add(info)
        self._broadcast_service(info, _REGISTER_TIME, None)

    def update_service(self, info: ServiceInfo) -> None:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service."""

        self.registry.update(info)
        self._broadcast_service(info, _REGISTER_TIME, None)

    def _broadcast_service(self, info: ServiceInfo, interval: int, ttl: Optional[int]) -> None:
        """Send a broadcasts to announce a service at intervals."""
        now = current_time_millis()
        next_time = now
        i = 0
        while i < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue

            self.send_service_broadcast(info, ttl)
            i += 1
            next_time += interval

    def send_service_broadcast(self, info: ServiceInfo, ttl: Optional[int]) -> None:
        """Send a broadcast to announce a service."""
        self.send(self.generate_service_broadcast(info, ttl))

    def generate_service_broadcast(self, info: ServiceInfo, ttl: Optional[int]) -> DNSOutgoing:
        """Generate a broadcast to announce a service."""
        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
        self._add_broadcast_answer(out, info, ttl)
        return out

    def send_service_query(self, info: ServiceInfo) -> None:
        """Send a query to lookup a service."""
        self.send(self.generate_service_query(info))

    def generate_service_query(self, info: ServiceInfo) -> DNSOutgoing:  # pylint: disable=no-self-use
        """Generate a query to lookup a service."""
        out = DNSOutgoing(_FLAGS_QR_QUERY | _FLAGS_AA)
        # https://datatracker.ietf.org/doc/html/rfc6762#section-8.1
        # Because of the mDNS multicast rate-limiting
        # rules, the probes SHOULD be sent as "QU" questions with the unicast-
        # response bit set, to allow a defending host to respond immediately
        # via unicast, instead of potentially having to wait before replying
        # via multicast.
        #
        # _CLASS_UNIQUE is the "QU" bit
        out.add_question(DNSQuestion(info.type, _TYPE_PTR, _CLASS_IN | _CLASS_UNIQUE))
        out.add_authorative_answer(info.dns_pointer(created=current_time_millis()))
        return out

    def _add_broadcast_answer(  # pylint: disable=no-self-use
        self, out: DNSOutgoing, info: ServiceInfo, override_ttl: Optional[int]
    ) -> None:
        """Add answers to broadcast a service."""
        now = current_time_millis()
        other_ttl = info.other_ttl if override_ttl is None else override_ttl
        host_ttl = info.host_ttl if override_ttl is None else override_ttl
        out.add_answer_at_time(info.dns_pointer(override_ttl=other_ttl, created=now), 0)
        out.add_answer_at_time(info.dns_service(override_ttl=host_ttl, created=now), 0)
        out.add_answer_at_time(info.dns_text(override_ttl=other_ttl, created=now), 0)
        for dns_address in info.dns_addresses(override_ttl=host_ttl, created=now):
            out.add_answer_at_time(dns_address, 0)

    def unregister_service(self, info: ServiceInfo) -> None:
        """Unregister a service."""
        self.registry.remove(info)
        self._broadcast_service(info, _UNREGISTER_TIME, 0)

    def generate_unregister_all_services(self) -> Optional[DNSOutgoing]:
        """Generate a DNSOutgoing goodbye for all services and remove them from the registry."""
        service_infos = self.registry.get_service_infos()
        if not service_infos:
            return None
        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
        for info in service_infos:
            self._add_broadcast_answer(out, info, 0)
        self.registry.remove(service_infos)
        return out

    def unregister_all_services(self) -> None:
        """Unregister all registered services."""
        # Send Goodbye packets https://datatracker.ietf.org/doc/html/rfc6762#section-10.1
        out = self.generate_unregister_all_services()
        if not out:
            return
        now = current_time_millis()
        next_time = now
        i = 0
        while i < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue
            self.send(out)
            i += 1
            next_time += _UNREGISTER_TIME

    def check_service(
        self, info: ServiceInfo, allow_name_change: bool, cooperating_responders: bool = False
    ) -> None:
        """Checks the network for a unique service name, modifying the
        ServiceInfo passed in if it is not unique."""
        instance_name = instance_name_from_service_info(info)
        if cooperating_responders:
            return
        next_instance_number = 2
        next_time = now = current_time_millis()
        i = 0
        while i < 3:
            # check for a name conflict
            while self.cache.current_entry_with_name_and_alias(info.type, info.name):
                if not allow_name_change:
                    raise NonUniqueNameException

                # change the name and look for a conflict
                info.name = '%s-%s.%s' % (instance_name, next_instance_number, info.type)
                next_instance_number += 1
                service_type_name(info.name)
                next_time = now
                i = 0

            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue

            self.send_service_query(info)
            i += 1
            next_time += _CHECK_TIME

    def add_listener(
        self, listener: RecordUpdateListener, question: Optional[Union[DNSQuestion, List[DNSQuestion]]]
    ) -> None:
        """Adds a listener for a given question.  The listener will have
        its update_record method called when information is available to
        answer the question(s).

        This function is threadsafe
        """
        assert self.loop is not None
        self.loop.call_soon_threadsafe(self.record_manager.async_add_listener, listener, question)

    def remove_listener(self, listener: RecordUpdateListener) -> None:
        """Removes a listener.

        This function is threadsafe
        """
        assert self.loop is not None
        self.loop.call_soon_threadsafe(self.record_manager.async_remove_listener, listener)

    def async_add_listener(
        self, listener: RecordUpdateListener, question: Optional[Union[DNSQuestion, List[DNSQuestion]]]
    ) -> None:
        """Adds a listener for a given question.  The listener will have
        its update_record method called when information is available to
        answer the question(s).

        This function is not threadsafe and must be called in the eventloop.
        """
        self.record_manager.async_add_listener(listener, question)

    def async_remove_listener(self, listener: RecordUpdateListener) -> None:
        """Removes a listener.

        This function is not threadsafe and must be called in the eventloop.
        """
        self.record_manager.async_remove_listener(listener)

    def handle_response(self, msg: DNSIncoming) -> None:
        """Deal with incoming response packets.  All answers
        are held in the cache, and listeners are notified."""
        self.record_manager.async_updates_from_response(msg)

    def handle_assembled_query(
        self,
        packets: List[DNSIncoming],
        addr: str,
        port: int,
        v6_flow_scope: Union[Tuple[()], Tuple[int, int]] = (),
    ) -> None:
        """Respond to a (re)assembled query.

        If the protocol recieved packets with the TC bit set, it will
        wait a bit for the rest of the packets and only call
        handle_assembled_query once it has a complete set of packets
        or the timer expires. If the TC bit is not set, a single
        packet will be in packets.
        """
        unicast_out, multicast_out = self.query_handler.async_response(packets, addr, port)
        if unicast_out:
            self.async_send(unicast_out, addr, port, v6_flow_scope)
        if multicast_out:
            self.async_send(multicast_out, None, _MDNS_PORT)

    def send(
        self,
        out: DNSOutgoing,
        addr: Optional[str] = None,
        port: int = _MDNS_PORT,
        v6_flow_scope: Union[Tuple[()], Tuple[int, int]] = (),
    ) -> None:
        """Sends an outgoing packet threadsafe."""
        assert self.loop is not None
        self.loop.call_soon_threadsafe(self.async_send, out, addr, port, v6_flow_scope)

    def async_send(
        self,
        out: DNSOutgoing,
        addr: Optional[str] = None,
        port: int = _MDNS_PORT,
        v6_flow_scope: Union[Tuple[()], Tuple[int, int]] = (),
    ) -> None:
        """Sends an outgoing packet."""
        for packet_num, packet in enumerate(out.packets()):
            if len(packet) > _MAX_MSG_ABSOLUTE:
                self.log_warning_once("Dropping %r over-sized packet (%d bytes) %r", out, len(packet), packet)
                return
            log.debug(
                'Sending to (%s, %d) (%d bytes #%d) %r as %r...',
                addr,
                port,
                len(packet),
                packet_num + 1,
                out,
                packet,
            )
            for transport in self.engine.senders:
                if self._GLOBAL_DONE:
                    return
                s = transport.get_extra_info('socket')
                if addr is None:
                    real_addr = _MDNS_ADDR6 if s.family == socket.AF_INET6 else _MDNS_ADDR
                elif not can_send_to(s, addr):
                    continue
                else:
                    real_addr = addr
                transport.sendto(packet, (real_addr, port or _MDNS_PORT, *v6_flow_scope))

    def _close(self) -> None:
        """Set global done and remove all service listeners."""
        if self._GLOBAL_DONE:
            return
        self.remove_all_service_listeners()
        self._GLOBAL_DONE = True

    def _shutdown_threads(self) -> None:
        """Shutdown any threads."""
        self.notify_all()
        if not self._loop_thread:
            return
        assert self.loop is not None
        shutdown_loop(self.loop)
        self._loop_thread.join()
        self._loop_thread = None

    def close(self) -> None:
        """Ends the background threads, and prevent this instance from
        servicing further queries.

        This method is idempotent and irreversible.
        """
        self.unregister_all_services()
        self._close()
        self.engine.close()
        self._shutdown_threads()

    async def _async_close(self) -> None:
        """Ends the background threads, and prevent this instance from
        servicing further queries.

        This method is idempotent and irreversible.

        This call only intended to be used by AsyncZeroconf

        Callers are responsible for unregistering all services
        before calling this function
        """
        self._close()
        await self.engine._async_close()  # pylint: disable=protected-access
        self._shutdown_threads()

    def __enter__(self) -> 'Zeroconf':
        return self

    def __exit__(  # pylint: disable=useless-return
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Optional[bool]:
        self.close()
        return None
