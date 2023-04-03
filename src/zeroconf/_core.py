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
import itertools
import logging
import random
import socket
import sys
import threading
from types import TracebackType  # noqa # used in type hints
from typing import Any, Awaitable, Dict, List, Optional, Tuple, Type, Union, cast

from ._cache import DNSCache
from ._dns import DNSQuestion, DNSQuestionType
from ._exceptions import NonUniqueNameException, NotRunningException
from ._handlers import (
    MulticastOutgoingQueue,
    QueryHandler,
    RecordManager,
    construct_outgoing_multicast_answers,
    construct_outgoing_unicast_answers,
)
from ._history import QuestionHistory
from ._logger import QuietLogger, log
from ._protocol.incoming import DNSIncoming
from ._protocol.outgoing import DNSOutgoing
from ._services import ServiceListener
from ._services.browser import ServiceBrowser
from ._services.info import ServiceInfo, instance_name_from_service_info
from ._services.registry import ServiceRegistry
from ._updates import RecordUpdate, RecordUpdateListener
from ._utils.asyncio import (
    await_awaitable,
    get_running_loop,
    run_coro_with_timeout,
    shutdown_loop,
    wait_event_or_timeout,
)
from ._utils.name import service_type_name
from ._utils.net import (
    InterfaceChoice,
    InterfacesType,
    IPVersion,
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
    _MAX_MSG_ABSOLUTE,
    _MDNS_ADDR,
    _MDNS_ADDR6,
    _MDNS_PORT,
    _ONE_SECOND,
    _REGISTER_TIME,
    _STARTUP_TIMEOUT,
    _TYPE_PTR,
    _UNREGISTER_TIME,
)

_TC_DELAY_RANDOM_INTERVAL = (400, 500)
# The maximum amont of time to delay a multicast
# response in order to aggregate answers
_AGGREGATION_DELAY = 500  # ms
# The maximum amont of time to delay a multicast
# response in order to aggregate answers after
# it has already been delayed to protect the network
# from excessive traffic. We use a shorter time
# window here as we want to _try_ to answer all
# queries in under 1350ms while protecting
# the network from excessive traffic to ensure
# a service info request with two questions
# can be answered in the default timeout of
# 3000ms
_PROTECTED_AGGREGATION_DELAY = 200  # ms

_CLOSE_TIMEOUT = 3000  # ms
_REGISTER_BROADCASTS = 3


class _WrappedTransport:
    """A wrapper for transports."""

    __slots__ = (
        'transport',
        'is_ipv6',
        'sock',
        'fileno',
        'sock_name',
    )

    def __init__(
        self,
        transport: asyncio.DatagramTransport,
        is_ipv6: bool,
        sock: socket.socket,
        fileno: int,
        sock_name: Any,
    ) -> None:
        """Initialize the wrapped transport.

        These attributes are used when sending packets.
        """
        self.transport = transport
        self.is_ipv6 = is_ipv6
        self.sock = sock
        self.fileno = fileno
        self.sock_name = sock_name


def _make_wrapped_transport(transport: asyncio.DatagramTransport) -> _WrappedTransport:
    """Make a wrapped transport."""
    sock: socket.socket = transport.get_extra_info('socket')
    return _WrappedTransport(
        transport=transport,
        is_ipv6=sock.family == socket.AF_INET6,
        sock=sock,
        fileno=sock.fileno(),
        sock_name=sock.getsockname(),
    )


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
        self.readers: List[_WrappedTransport] = []
        self.senders: List[_WrappedTransport] = []
        self.running_event: Optional[asyncio.Event] = None
        self._listen_socket = listen_socket
        self._respond_sockets = respond_sockets
        self._cleanup_timer: Optional[asyncio.TimerHandle] = None

    def setup(self, loop: asyncio.AbstractEventLoop, loop_thread_ready: Optional[threading.Event]) -> None:
        """Set up the instance."""
        self.loop = loop
        self.running_event = asyncio.Event()
        self.loop.create_task(self._async_setup(loop_thread_ready))

    async def _async_setup(self, loop_thread_ready: Optional[threading.Event]) -> None:
        """Set up the instance."""
        assert self.loop is not None
        self._cleanup_timer = self.loop.call_later(_CACHE_CLEANUP_INTERVAL, self._async_cache_cleanup)
        await self._async_create_endpoints()
        assert self.running_event is not None
        self.running_event.set()
        if loop_thread_ready:
            loop_thread_ready.set()

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
            self.readers.append(_make_wrapped_transport(cast(asyncio.DatagramTransport, transport)))
            if s in sender_sockets:
                self.senders.append(_make_wrapped_transport(cast(asyncio.DatagramTransport, transport)))

    def _async_cache_cleanup(self) -> None:
        """Periodic cache cleanup."""
        now = current_time_millis()
        self.zc.question_history.async_expire(now)
        self.zc.record_manager.async_updates(
            now, [RecordUpdate(record, record) for record in self.zc.cache.async_expire(now)]
        )
        self.zc.record_manager.async_updates_complete(False)
        assert self.loop is not None
        self._cleanup_timer = self.loop.call_later(_CACHE_CLEANUP_INTERVAL, self._async_cache_cleanup)

    async def _async_close(self) -> None:
        """Cancel and wait for the cleanup task to finish."""
        self._async_shutdown()
        await asyncio.sleep(0)  # flush out any call soons
        assert self._cleanup_timer is not None
        self._cleanup_timer.cancel()

    def _async_shutdown(self) -> None:
        """Shutdown transports and sockets."""
        assert self.running_event is not None
        self.running_event.clear()
        for wrapped_transport in itertools.chain(self.senders, self.readers):
            wrapped_transport.transport.close()

    def close(self) -> None:
        """Close from sync context.

        While it is not expected during normal operation,
        this function may raise EventLoopBlocked if the underlying
        call to `_async_close` cannot be completed.
        """
        assert self.loop is not None
        # Guard against Zeroconf.close() being called from the eventloop
        if get_running_loop() == self.loop:
            self._async_shutdown()
            return
        if not self.loop.is_running():
            return
        run_coro_with_timeout(self._async_close(), self.loop, _CLOSE_TIMEOUT)


class AsyncListener(asyncio.Protocol, QuietLogger):

    """A Listener is used by this module to listen on the multicast
    group to which DNS messages are sent, allowing the implementation
    to cache information as it arrives.

    It requires registration with an Engine object in order to have
    the read() method called when a socket is available for reading."""

    __slots__ = ('zc', 'data', 'last_time', 'transport', 'sock_description', '_deferred', '_timers')

    def __init__(self, zc: 'Zeroconf') -> None:
        self.zc = zc
        self.data: Optional[bytes] = None
        self.last_time: float = 0
        self.transport: Optional[_WrappedTransport] = None
        self.sock_description: Optional[str] = None
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
        data_len = len(data)

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
                'Ignoring duplicate message received from %r:%r [socket %s] (%d bytes) as [%r]',
                addr,
                port,
                self.sock_description,
                data_len,
                data,
            )
            return

        if data_len > _MAX_MSG_ABSOLUTE:
            # Guard against oversized packets to ensure bad implementations cannot overwhelm
            # the system.
            log.debug(
                "Discarding incoming packet with length %s, which is larger "
                "than the absolute maximum size of %s",
                data_len,
                _MAX_MSG_ABSOLUTE,
            )
            return

        msg = DNSIncoming(data, (addr, port), scope, now)
        if msg.valid:
            log.debug(
                'Received from %r:%r [socket %s]: %r (%d bytes) as [%r]',
                addr,
                port,
                self.sock_description,
                msg,
                data_len,
                data,
            )
        else:
            log.debug(
                'Received from %r:%r [socket %s]: (%d bytes) [%r]',
                addr,
                port,
                self.sock_description,
                data_len,
                data,
            )
            return

        if not msg.is_query():
            self.zc.handle_response(msg)
            return

        self.handle_query_or_defer(msg, addr, port, self.transport, v6_flow_scope)

    def handle_query_or_defer(
        self,
        msg: DNSIncoming,
        addr: str,
        port: int,
        transport: _WrappedTransport,
        v6_flow_scope: Union[Tuple[()], Tuple[int, int]] = (),
    ) -> None:
        """Deal with incoming query packets.  Provides a response if
        possible."""
        if not msg.truncated:
            self._respond_query(msg, addr, port, transport, v6_flow_scope)
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
            delay, self._respond_query, None, addr, port, transport, v6_flow_scope
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
        transport: _WrappedTransport,
        v6_flow_scope: Union[Tuple[()], Tuple[int, int]] = (),
    ) -> None:
        """Respond to a query and reassemble any truncated deferred packets."""
        self._cancel_any_timers_for_addr(addr)
        packets = self._deferred.pop(addr, [])
        if msg:
            packets.append(msg)

        self.zc.handle_assembled_query(packets, addr, port, transport, v6_flow_scope)

    def error_received(self, exc: Exception) -> None:
        """Likely socket closed or IPv6."""
        # We preformat the message string with the socket as we want
        # log_exception_once to log a warrning message once PER EACH
        # different socket in case there are problems with multiple
        # sockets
        msg_str = f"Error with socket {self.sock_description}): %s"
        self.log_exception_once(exc, msg_str, exc)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        wrapped_transport = _make_wrapped_transport(cast(asyncio.DatagramTransport, transport))
        self.transport = wrapped_transport
        self.sock_description = f"{wrapped_transport.fileno} ({wrapped_transport.sock_name})"

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Handle connection lost."""


def async_send_with_transport(
    log_debug: bool,
    transport: _WrappedTransport,
    packet: bytes,
    packet_num: int,
    out: DNSOutgoing,
    addr: Optional[str],
    port: int,
    v6_flow_scope: Union[Tuple[()], Tuple[int, int]] = (),
) -> None:
    ipv6_socket = transport.is_ipv6
    if addr is None:
        real_addr = _MDNS_ADDR6 if ipv6_socket else _MDNS_ADDR
    else:
        real_addr = addr
        if not can_send_to(ipv6_socket, real_addr):
            return
    if log_debug:
        log.debug(
            'Sending to (%s, %d) via [socket %s (%s)] (%d bytes #%d) %r as %r...',
            real_addr,
            port or _MDNS_PORT,
            transport.fileno,
            transport.sock_name,
            len(packet),
            packet_num + 1,
            out,
            packet,
        )
    # Get flowinfo and scopeid for the IPV6 socket to create a complete IPv6
    # address tuple: https://docs.python.org/3.6/library/socket.html#socket-families
    if ipv6_socket and not v6_flow_scope:
        _, _, sock_flowinfo, sock_scopeid = transport.sock_name
        v6_flow_scope = (sock_flowinfo, sock_scopeid)
    transport.transport.sendto(packet, (real_addr, port or _MDNS_PORT, *v6_flow_scope))


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

        self.done = False

        if apple_p2p and sys.platform != 'darwin':
            raise RuntimeError('Option `apple_p2p` is not supported on non-Apple platforms.')

        self.unicast = unicast
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

        self._out_queue = MulticastOutgoingQueue(self, 0, _AGGREGATION_DELAY)
        self._out_delay_queue = MulticastOutgoingQueue(self, _ONE_SECOND, _PROTECTED_AGGREGATION_DELAY)

        self.start()

    @property
    def started(self) -> bool:
        """Check if the instance has started."""
        return bool(not self.done and self.engine.running_event and self.engine.running_event.is_set())

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
        """Wait for start up for actions that require a running Zeroconf instance.

        Throws NotRunningException if the instance is not running or could
        not be started.
        """
        if self.done:  # If the instance was shutdown from under us, raise immediately
            raise NotRunningException
        assert self.engine.running_event is not None
        await wait_event_or_timeout(self.engine.running_event, timeout=_STARTUP_TIMEOUT)
        if not self.engine.running_event.is_set() or self.done:
            raise NotRunningException

    @property
    def listeners(self) -> List[RecordUpdateListener]:
        return self.record_manager.listeners

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
        (if you want this behavior set `cooperating_responders` to `True`).

        While it is not expected during normal operation,
        this function may raise EventLoopBlocked if the underlying
        call to `register_service` cannot be completed.
        """
        assert self.loop is not None
        run_coro_with_timeout(
            await_awaitable(
                self.async_register_service(info, ttl, allow_name_change, cooperating_responders)
            ),
            self.loop,
            _REGISTER_TIME * _REGISTER_BROADCASTS,
        )

    async def async_register_service(
        self,
        info: ServiceInfo,
        ttl: Optional[int] = None,
        allow_name_change: bool = False,
        cooperating_responders: bool = False,
    ) -> Awaitable:
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

        info.set_server_if_missing()
        await self.async_wait_for_start()
        await self.async_check_service(info, allow_name_change, cooperating_responders)
        self.registry.async_add(info)
        return asyncio.ensure_future(self._async_broadcast_service(info, _REGISTER_TIME, None))

    def update_service(self, info: ServiceInfo) -> None:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service.

        While it is not expected during normal operation,
        this function may raise EventLoopBlocked if the underlying
        call to `async_update_service` cannot be completed.
        """
        assert self.loop is not None
        run_coro_with_timeout(
            await_awaitable(self.async_update_service(info)), self.loop, _REGISTER_TIME * _REGISTER_BROADCASTS
        )

    async def async_update_service(self, info: ServiceInfo) -> Awaitable:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service."""
        self.registry.async_update(info)
        return asyncio.ensure_future(self._async_broadcast_service(info, _REGISTER_TIME, None))

    async def _async_broadcast_service(
        self,
        info: ServiceInfo,
        interval: int,
        ttl: Optional[int],
        broadcast_addresses: bool = True,
    ) -> None:
        """Send a broadcasts to announce a service at intervals."""
        for i in range(_REGISTER_BROADCASTS):
            if i != 0:
                await asyncio.sleep(millis_to_seconds(interval))
            self.async_send(self.generate_service_broadcast(info, ttl, broadcast_addresses))

    def generate_service_broadcast(
        self,
        info: ServiceInfo,
        ttl: Optional[int],
        broadcast_addresses: bool = True,
    ) -> DNSOutgoing:
        """Generate a broadcast to announce a service."""
        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
        self._add_broadcast_answer(out, info, ttl, broadcast_addresses)
        return out

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
        self,
        out: DNSOutgoing,
        info: ServiceInfo,
        override_ttl: Optional[int],
        broadcast_addresses: bool = True,
    ) -> None:
        """Add answers to broadcast a service."""
        now = current_time_millis()
        other_ttl = info.other_ttl if override_ttl is None else override_ttl
        host_ttl = info.host_ttl if override_ttl is None else override_ttl
        out.add_answer_at_time(info.dns_pointer(override_ttl=other_ttl, created=now), 0)
        out.add_answer_at_time(info.dns_service(override_ttl=host_ttl, created=now), 0)
        out.add_answer_at_time(info.dns_text(override_ttl=other_ttl, created=now), 0)
        if broadcast_addresses:
            for dns_address in info.dns_addresses(override_ttl=host_ttl, created=now):
                out.add_answer_at_time(dns_address, 0)

    def unregister_service(self, info: ServiceInfo) -> None:
        """Unregister a service.

        While it is not expected during normal operation,
        this function may raise EventLoopBlocked if the underlying
        call to `async_unregister_service` cannot be completed.
        """
        assert self.loop is not None
        run_coro_with_timeout(
            self.async_unregister_service(info), self.loop, _UNREGISTER_TIME * _REGISTER_BROADCASTS
        )

    async def async_unregister_service(self, info: ServiceInfo) -> Awaitable:
        """Unregister a service."""
        info.set_server_if_missing()
        self.registry.async_remove(info)
        # If another server uses the same addresses, we do not want to send
        # goodbye packets for the address records

        assert info.server is not None
        entries = self.registry.async_get_infos_server(info.server)
        broadcast_addresses = not bool(entries)
        return asyncio.ensure_future(
            self._async_broadcast_service(info, _UNREGISTER_TIME, 0, broadcast_addresses)
        )

    def generate_unregister_all_services(self) -> Optional[DNSOutgoing]:
        """Generate a DNSOutgoing goodbye for all services and remove them from the registry."""
        service_infos = self.registry.async_get_service_infos()
        if not service_infos:
            return None
        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
        for info in service_infos:
            self._add_broadcast_answer(out, info, 0)
        self.registry.async_remove(service_infos)
        return out

    async def async_unregister_all_services(self) -> None:
        """Unregister all registered services.

        Unlike async_register_service and async_unregister_service, this
        method does not return a future and is always expected to be
        awaited since its only called at shutdown.
        """
        # Send Goodbye packets https://datatracker.ietf.org/doc/html/rfc6762#section-10.1
        out = self.generate_unregister_all_services()
        if not out:
            return
        for i in range(_REGISTER_BROADCASTS):
            if i != 0:
                await asyncio.sleep(millis_to_seconds(_UNREGISTER_TIME))
            self.async_send(out)

    def unregister_all_services(self) -> None:
        """Unregister all registered services.

        While it is not expected during normal operation,
        this function may raise EventLoopBlocked if the underlying
        call to `async_unregister_all_services` cannot be completed.
        """
        assert self.loop is not None
        run_coro_with_timeout(
            self.async_unregister_all_services(), self.loop, _UNREGISTER_TIME * _REGISTER_BROADCASTS
        )

    async def async_check_service(
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
        while i < _REGISTER_BROADCASTS:
            # check for a name conflict
            while self.cache.current_entry_with_name_and_alias(info.type, info.name):
                if not allow_name_change:
                    raise NonUniqueNameException

                # change the name and look for a conflict
                info.name = f'{instance_name}-{next_instance_number}.{info.type}'
                next_instance_number += 1
                service_type_name(info.name)
                next_time = now
                i = 0

            if now < next_time:
                await self.async_wait(next_time - now)
                now = current_time_millis()
                continue

            self.async_send(self.generate_service_query(info))
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
        transport: _WrappedTransport,
        v6_flow_scope: Union[Tuple[()], Tuple[int, int]] = (),
    ) -> None:
        """Respond to a (re)assembled query.

        If the protocol recieved packets with the TC bit set, it will
        wait a bit for the rest of the packets and only call
        handle_assembled_query once it has a complete set of packets
        or the timer expires. If the TC bit is not set, a single
        packet will be in packets.
        """
        now = packets[0].now
        ucast_source = port != _MDNS_PORT
        question_answers = self.query_handler.async_response(packets, ucast_source)
        if question_answers.ucast:
            questions = packets[0].questions
            id_ = packets[0].id
            out = construct_outgoing_unicast_answers(question_answers.ucast, ucast_source, questions, id_)
            # When sending unicast, only send back the reply
            # via the same socket that it was recieved from
            # as we know its reachable from that socket
            self.async_send(out, addr, port, v6_flow_scope, transport)
        if question_answers.mcast_now:
            self.async_send(construct_outgoing_multicast_answers(question_answers.mcast_now))
        if question_answers.mcast_aggregate:
            self._out_queue.async_add(now, question_answers.mcast_aggregate)
        if question_answers.mcast_aggregate_last_second:
            # https://datatracker.ietf.org/doc/html/rfc6762#section-14
            # If we broadcast it in the last second, we have to delay
            # at least a second before we send it again
            self._out_delay_queue.async_add(now, question_answers.mcast_aggregate_last_second)

    def send(
        self,
        out: DNSOutgoing,
        addr: Optional[str] = None,
        port: int = _MDNS_PORT,
        v6_flow_scope: Union[Tuple[()], Tuple[int, int]] = (),
        transport: Optional[_WrappedTransport] = None,
    ) -> None:
        """Sends an outgoing packet threadsafe."""
        assert self.loop is not None
        self.loop.call_soon_threadsafe(self.async_send, out, addr, port, v6_flow_scope, transport)

    def async_send(
        self,
        out: DNSOutgoing,
        addr: Optional[str] = None,
        port: int = _MDNS_PORT,
        v6_flow_scope: Union[Tuple[()], Tuple[int, int]] = (),
        transport: Optional[_WrappedTransport] = None,
    ) -> None:
        """Sends an outgoing packet."""
        if self.done:
            return

        # If no transport is specified, we send to all the ones
        # with the same address family
        transports = [transport] if transport else self.engine.senders
        log_debug = log.isEnabledFor(logging.DEBUG)

        for packet_num, packet in enumerate(out.packets()):
            if len(packet) > _MAX_MSG_ABSOLUTE:
                self.log_warning_once("Dropping %r over-sized packet (%d bytes) %r", out, len(packet), packet)
                return
            for send_transport in transports:
                async_send_with_transport(
                    log_debug, send_transport, packet, packet_num, out, addr, port, v6_flow_scope
                )

    def _close(self) -> None:
        """Set global done and remove all service listeners."""
        if self.done:
            return
        self.remove_all_service_listeners()
        self.done = True

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
        assert self.loop is not None
        if self.loop.is_running():
            if self.loop == get_running_loop():
                log.warning(
                    "unregister_all_services skipped as it does blocking i/o; use AsyncZeroconf with asyncio"
                )
            else:
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
