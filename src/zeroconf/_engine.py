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
import sys
import threading
from typing import TYPE_CHECKING, cast

from ._record_update import RecordUpdate
from ._utils.asyncio import get_running_loop, run_coro_with_timeout
from ._utils.net import (
    InterfacesType,
    IPVersion,
    add_interface,
    add_multicast_member,
    drop_multicast_member,
    new_listen_socket,
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


def _listen_socket_supports(
    listen_socket: socket.socket, interface: str | tuple[tuple[str, int, int], int]
) -> bool:
    """Whether the fixed-family listen socket can join this interface's group."""
    if isinstance(interface, tuple):
        # An IPv6 interface can only be joined on an AF_INET6 socket.
        return listen_socket.family == socket.AF_INET6
    if listen_socket.family != socket.AF_INET6:
        # An IPv4 interface on an AF_INET socket.
        return True
    # An IPv4 interface on an AF_INET6 socket: only when it is dual-stack.
    supported = True
    try:
        supported = not listen_socket.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY)
    except OSError:
        # Windows rejects reading IPV6_V6ONLY on some sockets; assume supported
        # there (consistent with make_wrapped_transport) so a read failure can't
        # drive a rebuild loop. Elsewhere the read does not fail, so surface a
        # genuine error rather than mask an unreceivable family as supported.
        if sys.platform != "win32":
            raise
    return supported


def _without_transport(
    wrappers: list[_WrappedTransport], transport: asyncio.DatagramTransport
) -> list[_WrappedTransport]:
    """Return the wrappers whose underlying transport is not ``transport``."""
    return [wrapped for wrapped in wrappers if wrapped.transport is not transport]


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
            # _async_wrap_socket registers the transport with no await between
            # creating and registering it, and the pending-handle cleanup below
            # adds no await either, so a concurrent shutdown always sees ``s``
            # in exactly one place.
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
        disappeared, diffing on the bound address. A Default single-family
        instance's dual-use listen/responder socket is converted to a pure
        listener when moving to an explicit set; otherwise the shared listen
        socket is left intact. Returns whether any responder socket was
        added, so the caller can skip re-announcing when nothing appeared.
        """
        assert self.loop is not None
        normalized = normalize_interface_choice(interfaces, ip_version)
        desired = {_interface_key(interface): interface for interface in normalized}
        current = {wrapped.interface_key: wrapped for wrapped in self.senders}
        listen_transport = self._listen_transport
        listen_socket = listen_transport.sock if listen_transport is not None else None

        # The listen socket's family is fixed at construction, so a desired
        # interface of another family (e.g. an IPv6 interface added to an IPv4
        # instance) needs a fresh listen socket before senders are reconciled,
        # otherwise the current senders would be torn down with no replacements
        # bound.
        needs_rebuild = listen_socket is not None and any(
            not _listen_socket_supports(listen_socket, interface) for interface in desired.values()
        )

        # A Default single-family instance shares the listen socket as its only
        # sender (the dual-use socket). Moving it to an explicit interface set
        # abandons that optimization: demote the socket so it stops responding
        # (otherwise it would double every announcement on the overlapping
        # interface) and rebuild it as a pure listener (its existing group
        # memberships would otherwise collide with the new per-interface joins).
        # Once demoted it no longer counts as a per-interface sender, so the
        # interface it served gets a fresh responder like any other. The no-arg
        # refresh of a Default instance leaves desired == {its interface} and so
        # neither demotes nor rebuilds.
        if listen_transport is not None and any(
            wrapped.transport is listen_transport.transport for wrapped in self.senders
        ):
            listen_key = listen_transport.interface_key
            if any(key != listen_key for key in desired):
                self.senders = _without_transport(self.senders, listen_transport.transport)
                current.pop(listen_key, None)
                needs_rebuild = True

        if needs_rebuild:
            await self._async_rebuild_listen_socket(apple_p2p, desired, current)
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
        # Join the group and create the responder via the same primitive
        # construction uses, so setup and rescan stay in lockstep. These are
        # user-initiated reconciles, so a requested interface that fails to
        # come up is surfaced once at warning (deduped per interface so the
        # polling monitor doesn't spam) rather than only at debug.
        respond_socket = add_interface(listen_socket, interface, apple_p2p=apple_p2p, unicast=self.zc.unicast)
        if respond_socket is None:
            self.zc.log_warning_once(f"Interface {interface!r} not added")
            return False
        try:
            await self._async_wrap_socket(respond_socket, is_sender=True)
        except Exception:
            # Endpoint creation failed after the join/socket succeeded; roll
            # this interface back so it leaves no dangling group membership.
            respond_socket.close()
            if listen_socket is not None:
                drop_multicast_member(listen_socket, interface)
            raise
        return True

    def _async_remove_transport(self, transport: asyncio.DatagramTransport) -> None:
        """Drop a transport's protocol/reader/sender wrappers, cancelling its timers."""
        kept_protocols = []
        for protocol in self.protocols:
            if protocol.transport is not None and protocol.transport.transport is transport:
                # Cancel any pending TC-reassembly timers so one can't fire a
                # response against the transport we're about to close.
                protocol.cancel_pending_timers()
            else:
                kept_protocols.append(protocol)
        self.protocols = kept_protocols
        self.readers = _without_transport(self.readers, transport)
        self.senders = _without_transport(self.senders, transport)

    def _async_close_sender(self, wrapped: _WrappedTransport, listen_socket: socket.socket | None) -> None:
        """Drop a per-interface sender's wrappers/protocol and close its transport."""
        transport = wrapped.transport
        self._async_remove_transport(transport)
        try:
            if listen_socket is not None:
                drop_multicast_member(listen_socket, wrapped.multicast_interface)
        finally:
            # Release the socket even if a non-benign leave (e.g. EPERM) raises.
            transport.close()

    async def _async_rebuild_listen_socket(
        self,
        apple_p2p: bool,
        desired: dict[tuple[str, int], str | tuple[tuple[str, int, int], int]],
        current: dict[tuple[str, int], _WrappedTransport],
    ) -> None:
        """Replace the listen socket with one whose family covers the desired set.

        The listen socket's family is otherwise fixed at construction; this
        lets an instance start receiving a newly added address family, and is
        also used to convert a Default dual-use socket to a pure listener. The
        replacement family is derived from the desired set (not the
        requested ip_version, which an explicit list can contradict) so it
        always covers every desired interface and never needs an immediate
        re-rebuild. Interfaces that are staying are re-joined on the new socket,
        and the old socket is closed (releasing its memberships).
        """
        has_v6 = any(isinstance(interface, tuple) for interface in desired.values())
        has_v4 = any(not isinstance(interface, tuple) for interface in desired.values())
        if has_v4 and has_v6:
            family_version = IPVersion.All
        elif has_v6:
            family_version = IPVersion.V6Only
        else:
            family_version = IPVersion.V4Only
        new_listen = new_listen_socket(family_version, apple_p2p)
        if new_listen is None:
            raise RuntimeError("Failed to create a listen socket for the new interface family")
        try:
            for bind_address, interface in desired.items():
                # A staying interface that can't re-join on the new socket keeps
                # its sender but receives only via the shared socket it never
                # joined; surface that degraded state like _async_add_interface.
                if bind_address in current and not add_multicast_member(new_listen, interface):
                    self.zc.log_warning_once(
                        f"Interface {interface!r} could not re-join the multicast group "
                        "on the rebuilt listen socket"
                    )
            new_reader = await self._async_wrap_socket(new_listen, is_sender=False)
        except Exception:
            # Endpoint creation failed; close the unadopted socket (and its
            # joins) rather than leak it, mirroring _async_add_interface.
            new_listen.close()
            raise
        # A rebuild is only entered with a live listen socket, so the old
        # transport is always present.
        old_listen_transport = self._listen_transport
        assert old_listen_transport is not None
        self._listen_transport = new_reader
        old_transport = old_listen_transport.transport
        self._async_remove_transport(old_transport)
        old_transport.close()

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
