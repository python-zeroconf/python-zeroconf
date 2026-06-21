"""Multicast DNS Service Discovery for Python, v0.14-wmcbrine
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

from __future__ import annotations

import asyncio
import itertools
import socket
import threading
from typing import TYPE_CHECKING, cast

from ._record_update import RecordUpdate
from ._utils.asyncio import get_running_loop, run_coro_with_timeout
from ._utils.net import (
    InterfacesType,
    IPVersion,
    add_multicast_member,
    drop_multicast_member,
    new_respond_socket,
    normalize_interface_choice,
)
from ._utils.time import current_time_millis
from .const import _CACHE_CLEANUP_INTERVAL

if TYPE_CHECKING:
    from ._core import Zeroconf


from ._listener import AsyncListener
from ._transport import _strip_zone, _WrappedTransport, make_wrapped_transport

_CLOSE_TIMEOUT = 3000  # ms


def _interface_key(interface: str | tuple[tuple[str, int, int], int]) -> tuple[str, int]:
    """Return the (address, scope_id) an interface choice maps to, for diffing.

    Must produce the same key shape as ``_WrappedTransport.interface_key`` so
    the desired set (from ``normalize_interface_choice``) and the current set
    (from the bound senders) diff against each other.
    """
    if isinstance(interface, tuple):
        return (_strip_zone(interface[0][0]), interface[0][2])
    return (interface, 0)


class AsyncEngine:
    """An engine wraps sockets in the event loop."""

    __slots__ = (
        "_cleanup_timer",
        "_listen_socket",
        "_listen_transport",
        "_respond_sockets",
        "_setup_task",
        "loop",
        "protocols",
        "readers",
        "running_future",
        "senders",
        "zc",
    )

    def __init__(
        self,
        zeroconf: Zeroconf,
        listen_socket: socket.socket | None,
        respond_sockets: list[socket.socket],
    ) -> None:
        self.loop: asyncio.AbstractEventLoop | None = None
        self.zc = zeroconf
        self.protocols: list[AsyncListener] = []
        self.readers: list[_WrappedTransport] = []
        self.senders: list[_WrappedTransport] = []
        self.running_future: asyncio.Future[bool | None] | None = None
        self._listen_socket = listen_socket
        self._listen_transport: _WrappedTransport | None = None
        self._respond_sockets = respond_sockets
        self._cleanup_timer: asyncio.TimerHandle | None = None
        self._setup_task: asyncio.Task[None] | None = None

    def setup(
        self,
        loop: asyncio.AbstractEventLoop,
        loop_thread_ready: threading.Event | None,
    ) -> None:
        """Set up the instance."""
        self.loop = loop
        self.running_future = loop.create_future()
        self._setup_task = self.loop.create_task(self._async_setup(loop_thread_ready))

    async def _async_setup(self, loop_thread_ready: threading.Event | None) -> None:
        """Set up the instance."""
        self._async_schedule_next_cache_cleanup()
        await self._async_create_endpoints()
        assert self.running_future is not None
        if not self.running_future.done():
            self.running_future.set_result(True)
        if loop_thread_ready:
            loop_thread_ready.set()

    async def _async_create_endpoints(self) -> None:
        """Create endpoints to send and receive."""
        reader_sockets = []
        sender_sockets = []
        if self._listen_socket:
            reader_sockets.append(self._listen_socket)
        for s in self._respond_sockets:
            if s not in reader_sockets:
                reader_sockets.append(s)
            sender_sockets.append(s)

        for s in reader_sockets:
            reader = await self._async_wrap_socket(s, s in sender_sockets)
            # The wrap above does not await before returning, so releasing
            # the engine's pending handle here keeps ``s`` in exactly one
            # place from a concurrent shutdown's point of view.
            if s is self._listen_socket:
                # Keep a handle to the shared listen socket so interface
                # rescans can add/drop multicast memberships on it.
                self._listen_transport = reader
                self._listen_socket = None
            if s in self._respond_sockets:
                self._respond_sockets.remove(s)

    async def _async_wrap_socket(self, sock: socket.socket, is_sender: bool) -> _WrappedTransport:
        """Adopt a socket into a transport, register it, and return the reader wrapper."""
        assert self.loop is not None
        transport, protocol = await self.loop.create_datagram_endpoint(  # type: ignore[type-var]
            lambda: AsyncListener(self.zc),  # type: ignore[arg-type, return-value]
            sock=sock,
        )
        datagram_transport = cast(asyncio.DatagramTransport, transport)
        reader = make_wrapped_transport(datagram_transport)
        # No ``await`` between wrapping and registering so a concurrent
        # shutdown always sees the transport in exactly one place.
        self.protocols.append(cast(AsyncListener, protocol))
        self.readers.append(reader)
        if is_sender:
            self.senders.append(make_wrapped_transport(datagram_transport))
        return reader

    async def async_update_interfaces(
        self,
        interfaces: InterfacesType,
        ip_version: IPVersion,
        apple_p2p: bool,
    ) -> bool:
        """Reconcile sender/reader sockets to the live interface set.

        Adds a per-interface responder socket for each interface that
        appeared and tears down the socket for each interface that
        disappeared, diffing on the bound address. The shared listen
        socket (including the Default single-family dual-use socket) is
        never torn down here. Returns whether any responder socket was
        added, so the caller can skip re-announcing when nothing appeared.
        """
        assert self.loop is not None
        normalized = normalize_interface_choice(interfaces, ip_version)
        desired = {_interface_key(interface): interface for interface in normalized}
        current = {wrapped.interface_key: wrapped for wrapped in self.senders}
        listen_transport = self._listen_transport
        listen_socket = listen_transport.sock if listen_transport is not None else None

        for bind_address, wrapped in current.items():
            if bind_address in desired:
                continue
            if listen_transport is not None and wrapped.transport is listen_transport.transport:
                # The shared listen / dual-use socket is not a per-interface
                # sender; leaving the group or closing it would break receive.
                continue
            self._async_close_sender(wrapped, listen_socket)

        added = False
        for bind_address, interface in desired.items():
            if bind_address in current:
                continue
            if await self._async_add_interface(interface, listen_socket, apple_p2p):
                added = True
        return added

    async def _async_add_interface(
        self,
        interface: str | tuple[tuple[str, int, int], int],
        listen_socket: socket.socket | None,
        apple_p2p: bool,
    ) -> bool:
        """Join the multicast group and adopt a responder socket for one interface.

        Returns whether a responder socket was actually added.
        """
        # A unicast instance has no listen socket, so membership is only
        # ever managed when ``listen_socket`` is present. These are
        # user-initiated reconciles, so a requested interface that fails to
        # come up is surfaced once at warning (deduped per interface so the
        # polling monitor doesn't spam) rather than only at debug.
        if listen_socket is not None and not add_multicast_member(listen_socket, interface):
            self.zc.log_warning_once(f"Interface {interface!r} not added: could not join multicast group")
            return False
        respond_socket = new_respond_socket(interface, apple_p2p=apple_p2p, unicast=self.zc.unicast)
        if respond_socket is None:
            if listen_socket is not None:
                drop_multicast_member(listen_socket, interface)
            self.zc.log_warning_once(f"Interface {interface!r} not added: no responder socket")
            return False
        await self._async_wrap_socket(respond_socket, is_sender=True)
        return True

    def _async_close_sender(self, wrapped: _WrappedTransport, listen_socket: socket.socket | None) -> None:
        """Drop a per-interface sender's wrappers/protocol and close its transport."""
        transport = wrapped.transport
        self.protocols = [
            p for p in self.protocols if p.transport is None or p.transport.transport is not transport
        ]
        self.readers = [w for w in self.readers if w.transport is not transport]
        self.senders = [w for w in self.senders if w.transport is not transport]
        if listen_socket is not None:
            drop_multicast_member(listen_socket, wrapped.multicast_interface)
        transport.close()

    def _async_cache_cleanup(self) -> None:
        """Periodic cache cleanup."""
        now = current_time_millis()
        self.zc.question_history.async_expire(now)
        self.zc.record_manager.async_updates(
            now,
            [RecordUpdate(record, record) for record in self.zc.cache.async_expire(now)],
        )
        self.zc.record_manager.async_updates_complete(False)
        self._async_schedule_next_cache_cleanup()

    def _async_schedule_next_cache_cleanup(self) -> None:
        """Schedule the next cache cleanup."""
        loop = self.loop
        assert loop is not None
        self._cleanup_timer = loop.call_at(loop.time() + _CACHE_CLEANUP_INTERVAL, self._async_cache_cleanup)

    async def _async_close(self) -> None:
        """Cancel and wait for the cleanup task to finish."""
        assert self._setup_task is not None
        # Swallow CancelledError only if the setup task itself was
        # cancelled (close-before-start); outer-task cancellation must
        # propagate.
        try:
            await self._setup_task
        except asyncio.CancelledError:
            if not self._setup_task.cancelled():
                raise
        self._async_shutdown()
        await asyncio.sleep(0)  # flush out any call soons
        if self._cleanup_timer is not None:
            self._cleanup_timer.cancel()

    def _async_shutdown(self) -> None:
        """Shutdown transports and sockets; safe to call repeatedly."""
        assert self.running_future is not None
        assert self.loop is not None
        self.running_future = self.loop.create_future()
        # Cancel pending setup so it can't wrap fresh transports after
        # shutdown has started.
        if self._setup_task is not None and not self._setup_task.done():
            self._setup_task.cancel()
        for wrapped_transport in itertools.chain(self.senders, self.readers):
            wrapped_transport.transport.close()
        # Anything still here was never adopted by a transport.
        if self._listen_socket is not None:
            self._listen_socket.close()
            self._listen_socket = None
        for s in self._respond_sockets:
            s.close()
        self._respond_sockets = []

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
