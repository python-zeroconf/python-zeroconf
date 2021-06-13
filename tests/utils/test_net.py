#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for zeroconf._utils.net."""
from unittest.mock import Mock, patch

import errno
import ifaddr
import pytest
import unittest

from zeroconf._utils import net as netutils
import zeroconf as r


def _generate_mock_adapters():
    mock_lo0 = Mock(spec=ifaddr.Adapter)
    mock_lo0.nice_name = "lo0"
    mock_lo0.ips = [ifaddr.IP("127.0.0.1", 8, "lo0")]
    mock_lo0.index = 0
    mock_eth0 = Mock(spec=ifaddr.Adapter)
    mock_eth0.nice_name = "eth0"
    mock_eth0.ips = [ifaddr.IP(("2001:db8::", 1, 1), 8, "eth0")]
    mock_eth0.index = 1
    mock_eth1 = Mock(spec=ifaddr.Adapter)
    mock_eth1.nice_name = "eth1"
    mock_eth1.ips = [ifaddr.IP("192.168.1.5", 23, "eth1")]
    mock_eth1.index = 2
    mock_vtun0 = Mock(spec=ifaddr.Adapter)
    mock_vtun0.nice_name = "vtun0"
    mock_vtun0.ips = [ifaddr.IP("169.254.3.2", 16, "vtun0")]
    mock_vtun0.index = 3
    return [mock_eth0, mock_lo0, mock_eth1, mock_vtun0]


def test_ip6_to_address_and_index():
    """Test we can extract from mocked adapters."""
    adapters = _generate_mock_adapters()
    assert netutils.ip6_to_address_and_index(adapters, "2001:db8::") == (('2001:db8::', 1, 1), 1)
    with pytest.raises(RuntimeError):
        assert netutils.ip6_to_address_and_index(adapters, "2005:db8::")


def test_interface_index_to_ip6_address():
    """Test we can extract from mocked adapters."""
    adapters = _generate_mock_adapters()
    assert netutils.interface_index_to_ip6_address(adapters, 1) == ('2001:db8::', 1, 1)
    with pytest.raises(RuntimeError):
        assert netutils.interface_index_to_ip6_address(adapters, 6)


def test_ip6_addresses_to_indexes():
    """Test we can extract from mocked adapters."""
    interfaces = [1]
    with patch("zeroconf._utils.net.ifaddr.get_adapters", return_value=_generate_mock_adapters()):
        assert netutils.ip6_addresses_to_indexes(interfaces) == [(('2001:db8::', 1, 1), 1)]

    interfaces = ['2001:db8::']
    with patch("zeroconf._utils.net.ifaddr.get_adapters", return_value=_generate_mock_adapters()):
        assert netutils.ip6_addresses_to_indexes(interfaces) == [(('2001:db8::', 1, 1), 1)]


@pytest.mark.parametrize(
    "errno,expected_result",
    [(errno.EADDRINUSE, False), (errno.EADDRNOTAVAIL, False), (errno.EINVAL, False), (0, True)],
)
def test_add_multicast_member_socket_errors(errno, expected_result):
    """Test we handle socket errors when adding multicast members."""
    if errno:
        setsockopt_mock = unittest.mock.Mock(side_effect=OSError(errno, "Error: {}".format(errno)))
    else:
        setsockopt_mock = unittest.mock.Mock()
    fileno_mock = unittest.mock.PropertyMock(return_value=10)
    socket_mock = unittest.mock.Mock(setsockopt=setsockopt_mock, fileno=fileno_mock)
    assert r.add_multicast_member(socket_mock, "0.0.0.0") == expected_result


def test_autodetect_ip_version():
    """Tests for auto detecting IPVersion based on interface ips."""
    assert r.autodetect_ip_version(["1.3.4.5"]) is r.IPVersion.V4Only
    assert r.autodetect_ip_version([]) is r.IPVersion.V4Only
    assert r.autodetect_ip_version(["::1", "1.2.3.4"]) is r.IPVersion.All
    assert r.autodetect_ip_version(["::1"]) is r.IPVersion.V6Only
