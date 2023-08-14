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
import threading
from typing import TYPE_CHECKING, Any, Dict, List, Optional, Tuple, Union, cast

from ._logger import QuietLogger, log
from ._protocol.incoming import DNSIncoming
from ._updates import RecordUpdate
from ._utils.asyncio import get_running_loop, run_coro_with_timeout
from ._utils.time import current_time_millis, millis_to_seconds
from .const import (
    _CACHE_CLEANUP_INTERVAL,
    _DUPLICATE_PACKET_SUPPRESSION_INTERVAL,
    _MAX_MSG_ABSOLUTE,
)

if TYPE_CHECKING:
    from ._core import Zeroconf

_TC_DELAY_RANDOM_INTERVAL = (400, 500)

_CLOSE_TIMEOUT = 3000  # ms

_bytes = bytes

logging_DEBUG = logging.DEBUG


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

    __slots__ = (
        'loop',
        'zc',
        'protocols',
        'readers',
        'senders',
        'running_event',
        '_listen_socket',
        '_respond_sockets',
        '_cleanup_timer',
    )

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
            transport, protocol = await loop.create_datagram_endpoint(
                lambda: AsyncListener(self.zc), sock=s  # type: ignore[arg-type, return-value]
            )
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


class AsyncListener:

    """A Listener is used by this module to listen on the multicast
    group to which DNS messages are sent, allowing the implementation
    to cache information as it arrives.

    It requires registration with an Engine object in order to have
    the read() method called when a socket is available for reading."""

    __slots__ = (
        'zc',
        'data',
        'last_time',
        'last_message',
        'transport',
        'sock_description',
        '_deferred',
        '_timers',
    )

    def __init__(self, zc: 'Zeroconf') -> None:
        self.zc = zc
        self.data: Optional[bytes] = None
        self.last_time: float = 0
        self.last_message: Optional[DNSIncoming] = None
        self.transport: Optional[_WrappedTransport] = None
        self.sock_description: Optional[str] = None
        self._deferred: Dict[str, List[DNSIncoming]] = {}
        self._timers: Dict[str, asyncio.TimerHandle] = {}

    def datagram_received(
        self, data: _bytes, addrs: Union[Tuple[str, int], Tuple[str, int, int, int]]
    ) -> None:
        assert self.transport is not None
        data_len = len(data)
        debug = log.isEnabledFor(logging_DEBUG)

        if data_len > _MAX_MSG_ABSOLUTE:
            # Guard against oversized packets to ensure bad implementations cannot overwhelm
            # the system.
            if debug:
                log.debug(
                    "Discarding incoming packet with length %s, which is larger "
                    "than the absolute maximum size of %s",
                    data_len,
                    _MAX_MSG_ABSOLUTE,
                )
            return

        now = current_time_millis()
        if (
            self.data == data
            and (now - _DUPLICATE_PACKET_SUPPRESSION_INTERVAL) < self.last_time
            and self.last_message is not None
            and not self.last_message.has_qu_question()
        ):
            # Guard against duplicate packets
            if debug:
                log.debug(
                    'Ignoring duplicate message with no unicast questions received from %s [socket %s] (%d bytes) as [%r]',
                    addrs,
                    self.sock_description,
                    data_len,
                    data,
                )
            return

        v6_flow_scope: Union[Tuple[()], Tuple[int, int]] = ()
        if len(addrs) == 2:
            # https://github.com/python/mypy/issues/1178
            addr, port = addrs  # type: ignore
            scope = None
        else:
            # https://github.com/python/mypy/issues/1178
            addr, port, flow, scope = addrs  # type: ignore
            if debug:  # pragma: no branch
                log.debug('IPv6 scope_id %d associated to the receiving interface', scope)
            v6_flow_scope = (flow, scope)

        msg = DNSIncoming(data, (addr, port), scope, now)
        self.data = data
        self.last_time = now
        self.last_message = msg
        if msg.valid:
            if debug:
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
            if debug:
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
        QuietLogger.log_exception_once(exc, msg_str, exc)

    def connection_made(self, transport: asyncio.BaseTransport) -> None:
        wrapped_transport = _make_wrapped_transport(cast(asyncio.DatagramTransport, transport))
        self.transport = wrapped_transport
        self.sock_description = f"{wrapped_transport.fileno} ({wrapped_transport.sock_name})"

    def connection_lost(self, exc: Optional[Exception]) -> None:
        """Handle connection lost."""
