#!/usr/bin/env python

"""Unit tests for zeroconf._utils.ipaddress."""

from zeroconf._utils import ipaddress


def test_cached_ip_addresses_wrapper():
    """Test the cached_ip_addresses_wrapper."""
    assert ipaddress.cached_ip_addresses_wrapper('') is None
    assert ipaddress.cached_ip_addresses_wrapper('foo') is None
    assert ipaddress.cached_ip_addresses_wrapper(b'&\x06(\x00\x02 \x00\x01\x02H\x18\x93%\xc8\x19F') is None
