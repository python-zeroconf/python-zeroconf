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
import sys
from functools import lru_cache
from ipaddress import AddressValueError, IPv4Address, IPv6Address, NetmaskValueError
from typing import Any, Optional, Union

from .._dns import DNSAddress
from ..const import _TYPE_AAAA

bytes_ = bytes
int_ = int
IPADDRESS_SUPPORTS_SCOPE_ID = sys.version_info >= (3, 9, 0)


class ZeroconfIPv4Address(IPv4Address):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a new IPv4 address."""
        super().__init__(*args, **kwargs)
        self._str = super().__str__()

    def __str__(self) -> str:
        """Return the string representation of the IPv4 address."""
        return self._str


class ZeroconfIPv6Address(IPv6Address):
    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a new IPv6 address."""
        super().__init__(*args, **kwargs)
        self._str = super().__str__()

    def __str__(self) -> str:
        """Return the string representation of the IPv6 address."""
        return self._str


@lru_cache(maxsize=512)
def _cached_ip_addresses(address: Union[str, bytes, int]) -> Optional[Union[IPv4Address, IPv6Address]]:
    """Cache IP addresses."""
    try:
        return ZeroconfIPv4Address(address) or ZeroconfIPv6Address(address)
    except (AddressValueError, NetmaskValueError):
        raise ValueError(f'{address!r} does not appear to be an IPv4 or IPv6 address')


cached_ip_addresses_wrapper = _cached_ip_addresses


def get_ip_address_object_from_record(record: DNSAddress) -> Optional[Union[IPv4Address, IPv6Address]]:
    """Get the IP address object from the record."""
    if IPADDRESS_SUPPORTS_SCOPE_ID and record.type == _TYPE_AAAA and record.scope_id is not None:
        return ip_bytes_and_scope_to_address(record.address, record.scope_id)
    return cached_ip_addresses_wrapper(record.address)


def ip_bytes_and_scope_to_address(address: bytes_, scope: int_) -> Optional[Union[IPv4Address, IPv6Address]]:
    """Convert the bytes and scope to an IP address object."""
    base_address = cached_ip_addresses_wrapper(address)
    if base_address is not None and base_address.is_link_local:
        return cached_ip_addresses_wrapper(f"{base_address}%{scope}")
    return base_address


def str_without_scope_id(addr: Union[IPv4Address, IPv6Address]) -> str:
    """Return the string representation of the address without the scope id."""
    if IPADDRESS_SUPPORTS_SCOPE_ID and addr.version == 6:
        address_str = str(addr)
        return address_str.partition('%')[0]
    return str(addr)
