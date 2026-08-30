"""A pure python implementation of multicast DNS service discovery.

Licensed under LGPL-2.1-or-later; see COPYING for details. This file is
part of a continuously modified work; modification dates are recorded
in the project's git history.
"""

from __future__ import annotations

from functools import lru_cache
from ipaddress import AddressValueError, IPv4Address, IPv6Address, NetmaskValueError
from typing import Any

from .._dns import DNSAddress
from ..const import _TYPE_AAAA

bytes_ = bytes
int_ = int


class ZeroconfIPv4Address(IPv4Address):
    __slots__ = ("_hash", "_is_link_local", "_is_loopback", "_is_unspecified", "_str", "zc_integer")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a new IPv4 address."""
        super().__init__(*args, **kwargs)
        self._str = super().__str__()
        self._is_link_local = super().is_link_local
        self._is_unspecified = super().is_unspecified
        self._is_loopback = super().is_loopback
        self._hash = IPv4Address.__hash__(self)
        self.zc_integer = int(self)

    def __hash__(self) -> int:
        """Return the precomputed hash of the IPv4 address."""
        return self._hash

    def __str__(self) -> str:
        """Return the string representation of the IPv4 address."""
        return self._str

    @property
    def is_link_local(self) -> bool:
        """True for a link-local address."""
        return self._is_link_local

    @property
    def is_loopback(self) -> bool:
        """True for a loopback address."""
        return self._is_loopback

    @property
    def is_unspecified(self) -> bool:
        """True for an unspecified address."""
        return self._is_unspecified


class ZeroconfIPv6Address(IPv6Address):
    __slots__ = ("_hash", "_is_link_local", "_is_loopback", "_is_unspecified", "_str", "zc_integer")

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        """Initialize a new IPv6 address."""
        super().__init__(*args, **kwargs)
        self._str = super().__str__()
        self._is_link_local = super().is_link_local
        self._is_unspecified = super().is_unspecified
        self._is_loopback = super().is_loopback
        self._hash = IPv6Address.__hash__(self)
        self.zc_integer = int(self)

    def __hash__(self) -> int:
        """Return the precomputed hash of the IPv6 address."""
        return self._hash

    def __str__(self) -> str:
        """Return the string representation of the IPv6 address."""
        return self._str

    @property
    def is_link_local(self) -> bool:
        """True for a link-local address."""
        return self._is_link_local

    @property
    def is_loopback(self) -> bool:
        """True for a loopback address."""
        return self._is_loopback

    @property
    def is_unspecified(self) -> bool:
        """True for an unspecified address."""
        return self._is_unspecified


@lru_cache(maxsize=512)
def _cached_ip_addresses(
    address: str | bytes | int,
) -> ZeroconfIPv4Address | ZeroconfIPv6Address | None:
    """Cache IP addresses."""
    try:
        return ZeroconfIPv4Address(address)
    except (AddressValueError, NetmaskValueError):
        pass

    try:
        return ZeroconfIPv6Address(address)
    except (AddressValueError, NetmaskValueError):
        return None


cached_ip_addresses_wrapper = _cached_ip_addresses
cached_ip_addresses = cached_ip_addresses_wrapper


def get_ip_address_object_from_record(
    record: DNSAddress,
) -> ZeroconfIPv4Address | ZeroconfIPv6Address | None:
    """Get the IP address object from the record."""
    if record.type == _TYPE_AAAA and record.scope_id:
        return ip_bytes_and_scope_to_address(record.address, record.scope_id)
    return cached_ip_addresses_wrapper(record.address)


def ip_bytes_and_scope_to_address(
    address: bytes_ | str, scope: int_
) -> ZeroconfIPv4Address | ZeroconfIPv6Address | None:
    """Convert the bytes and scope to an IP address object."""
    base_address = cached_ip_addresses_wrapper(address)
    if base_address is not None and base_address.is_link_local:
        # Avoid expensive __format__ call by using PyUnicode_Join
        return cached_ip_addresses_wrapper("".join((str(base_address), "%", str(scope))))
    return base_address


def str_without_scope_id(addr: ZeroconfIPv4Address | ZeroconfIPv6Address) -> str:
    """Return the string representation of the address without the scope id."""
    if addr.version == 6:
        address_str = str(addr)
        return address_str.partition("%")[0]
    return str(addr)


__all__ = (
    "cached_ip_addresses",
    "get_ip_address_object_from_record",
    "ip_bytes_and_scope_to_address",
    "str_without_scope_id",
)
