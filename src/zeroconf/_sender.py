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

import logging
from typing import TYPE_CHECKING, Optional, Tuple, Union

from ._logger import QuietLogger, log
from ._protocol.outgoing import DNSOutgoing
from ._transport import _WrappedTransport
from ._utils.net import (
    can_send_to,
)
from .const import (
    _MAX_MSG_ABSOLUTE,
    _MDNS_ADDR,
    _MDNS_ADDR6,
    _MDNS_PORT,
)

if TYPE_CHECKING:
    from ._core import Zeroconf

_bytes = bytes
_int = int


def async_send_with_transport(
    log_debug: bool,
    transport: _WrappedTransport,
    packet: _bytes,
    packet_num: _int,
    out: DNSOutgoing,
    addr: Optional[str],
    port: _int,
    v6_flow_scope: Union[Tuple[()], Tuple[int, int]],
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
            "Sending to (%s, %d) via [socket %s (%s)] (%d bytes #%d) %r as %r...",
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


class _ZeroconfSender:
    """Send implementation for Zeroconf."""

    __slots__ = ("zc", "loop", "done", "engine")

    def __init__(self, zc: "Zeroconf") -> None:
        """Initialize the ZeroconfSender."""
        self.zc = zc
        self.loop = zc.loop
        self.done = zc.done
        self.engine = zc.engine

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
                QuietLogger.log_warning_once(
                    "Dropping %r over-sized packet (%d bytes) %r",
                    out,
                    len(packet),
                    packet,
                )
                return
            for send_transport in transports:
                async_send_with_transport(
                    log_debug,
                    send_transport,
                    packet,
                    packet_num,
                    out,
                    addr,
                    port,
                    v6_flow_scope,
                )
