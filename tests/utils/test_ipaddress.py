#!/usr/bin/env python

"""Unit tests for zeroconf._utils.ipaddress."""

from zeroconf._utils import ipaddress


def test_cached_ip_addresses_wrapper():
    """Test the cached_ip_addresses_wrapper."""
    assert ipaddress.cached_ip_addresses('') is None
    assert ipaddress.cached_ip_addresses('foo') is None
    assert (
        str(ipaddress.cached_ip_addresses(b'&\x06(\x00\x02 \x00\x01\x02H\x18\x93%\xc8\x19F'))
        == '2606:2800:220:1:248:1893:25c8:1946'
    )
