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
import socket
import sys
from typing import cast


def _strip_zone(address: str) -> str:
    """Drop a ``%zone`` suffix from an IPv6 address string."""
    percent = address.find("%")
    return address[:percent] if percent != -1 else address


class _WrappedTransport:
    """A wrapper for transports."""

    __slots__ = (
        "fileno",
        "is_ipv6",
        "multicast_index",
        "sock",
        "sock_name",
        "transport",
    )

    def __init__(
        self,
        transport: asyncio.DatagramTransport,
        is_ipv6: bool,
        sock: socket.socket,
        fileno: int,
        sock_name: tuple,
        multicast_index: int = 0,
    ) -> None:
        """Initialize the wrapped transport.

        ``multicast_index`` is the IPV6_MULTICAST_IF interface index the
        sender joined the group with, carried so a group leave uses the same
        index the join did (the bound socket's scope_id is 0 for global IPv6).
        """
        self.transport = transport
        self.is_ipv6 = is_ipv6
        self.sock = sock
        self.fileno = fileno
        self.sock_name = sock_name
        self.multicast_index = multicast_index

    @property
    def interface_key(self) -> tuple[str, int]:
        """The bound (address, scope_id) identifying this sender's interface.

        Used to diff senders against the desired interface set. The scope_id
        keeps link-local IPv6 addresses that repeat across interfaces (same
        address, different zone) from colliding to one key.
        """
        sock_name = self.sock_name
        if self.is_ipv6:
            scope_id = cast(int, sock_name[3]) if len(sock_name) > 3 else 0
            return (_strip_zone(sock_name[0]), scope_id)
        return (cast(str, sock_name[0]), 0)

    @property
    def multicast_interface(self) -> str | tuple[tuple[str, int, int], int]:
        """The interface value a group leave takes for this transport.

        For IPv6 this carries ``multicast_index`` (the index the join used),
        not the bound scope_id, so leave and join stay symmetric.
        """
        address, _scope_id = self.interface_key
        if self.is_ipv6:
            return ((address, 0, 0), self.multicast_index)
        return address


def make_wrapped_transport(transport: asyncio.DatagramTransport) -> _WrappedTransport:
    """Make a wrapped transport."""
    sock: socket.socket = transport.get_extra_info("socket")
    is_ipv6 = sock.family == socket.AF_INET6
    multicast_index = 0
    if is_ipv6:
        # IPV6_MULTICAST_IF holds the interface index new_respond_socket
        # joined the group with; capture it so a later group leave uses the
        # same index. Windows rejects reading the option (WSAEINVAL); there
        # the leave falls back to the default interface as it did before.
        try:
            multicast_index = sock.getsockopt(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF)
        except OSError:
            # Windows rejects reading IPV6_MULTICAST_IF (WSAEINVAL); the
            # default index 0 set above is kept there. On other platforms this
            # read does not fail, so re-raise rather than mask a genuine error
            # into a wrong-interface group leave.
            if sys.platform != "win32":
                raise
    return _WrappedTransport(
        transport=transport,
        is_ipv6=is_ipv6,
        sock=sock,
        fileno=sock.fileno(),
        sock_name=sock.getsockname(),
        multicast_index=multicast_index,
    )
