#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for zeroconf._utils.net."""
from unittest.mock import Mock, patch

import ifaddr
import pytest

from zeroconf._utils import net as netutils


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
