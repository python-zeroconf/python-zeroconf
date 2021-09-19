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

from ..const import (
    _FLAGS_QR_MASK,
    _FLAGS_QR_QUERY,
    _FLAGS_QR_RESPONSE,
    _FLAGS_TC,
)


class DNSMessage:
    """A base class for DNS messages."""

    __slots__ = ('flags',)

    def __init__(self, flags: int) -> None:
        """Construct a DNS message."""
        self.flags = flags

    def is_query(self) -> bool:
        """Returns true if this is a query."""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_QUERY

    def is_response(self) -> bool:
        """Returns true if this is a response."""
        return (self.flags & _FLAGS_QR_MASK) == _FLAGS_QR_RESPONSE

    @property
    def truncated(self) -> bool:
        """Returns true if this is a truncated."""
        return (self.flags & _FLAGS_TC) == _FLAGS_TC
