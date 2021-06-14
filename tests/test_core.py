#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf._core """

import itertools
import logging
import os
import pytest
import socket
import time
import unittest
import unittest.mock
from typing import cast

import zeroconf as r
from zeroconf import _core, const, ServiceBrowser, Zeroconf

from . import has_working_ipv6, _inject_response

log = logging.getLogger('zeroconf')
original_logging_level = logging.NOTSET


def setup_module():
    global original_logging_level
    original_logging_level = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    if original_logging_level != logging.NOTSET:
        log.setLevel(original_logging_level)


class TestReaper(unittest.TestCase):
    @unittest.mock.patch.object(_core, "_CACHE_CLEANUP_INTERVAL", 10)
    def test_reaper(self):
        zeroconf = _core.Zeroconf(interfaces=['127.0.0.1'])
        cache = zeroconf.cache
        original_entries = list(itertools.chain(*[cache.entries_with_name(name) for name in cache.names()]))
        record_with_10s_ttl = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 10, b'a')
        record_with_1s_ttl = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'b')
        zeroconf.cache.add(record_with_10s_ttl)
        zeroconf.cache.add(record_with_1s_ttl)
        entries_with_cache = list(itertools.chain(*[cache.entries_with_name(name) for name in cache.names()]))
        time.sleep(1)
        with zeroconf.engine.condition:
            zeroconf.engine._notify()
        time.sleep(0.1)
        entries = list(itertools.chain(*[cache.entries_with_name(name) for name in cache.names()]))
        zeroconf.close()
        assert entries != original_entries
        assert entries_with_cache != original_entries
        assert record_with_10s_ttl in entries
        assert record_with_1s_ttl not in entries


class Framework(unittest.TestCase):
    def test_launch_and_close(self):
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.All)
        rv.close()
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.Default)
        rv.close()

    def test_launch_and_close_context_manager(self):
        with r.Zeroconf(interfaces=r.InterfaceChoice.All) as rv:
            assert rv.done is False
        assert rv.done is True

        with r.Zeroconf(interfaces=r.InterfaceChoice.Default) as rv:
            assert rv.done is False
        assert rv.done is True

    def test_launch_and_close_unicast(self):
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.All, unicast=True)
        rv.close()
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.Default, unicast=True)
        rv.close()

    def test_close_multiple_times(self):
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.Default)
        rv.close()
        rv.close()

    @unittest.skipIf(not has_working_ipv6(), 'Requires IPv6')
    @unittest.skipIf(os.environ.get('SKIP_IPV6'), 'IPv6 tests disabled')
    def test_launch_and_close_v4_v6(self):
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.All, ip_version=r.IPVersion.All)
        rv.close()
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.Default, ip_version=r.IPVersion.All)
        rv.close()

    @unittest.skipIf(not has_working_ipv6(), 'Requires IPv6')
    @unittest.skipIf(os.environ.get('SKIP_IPV6'), 'IPv6 tests disabled')
    def test_launch_and_close_v6_only(self):
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.All, ip_version=r.IPVersion.V6Only)
        rv.close()
        rv = r.Zeroconf(interfaces=r.InterfaceChoice.Default, ip_version=r.IPVersion.V6Only)
        rv.close()

    def test_handle_response(self):
        def mock_incoming_msg(service_state_change: r.ServiceStateChange) -> r.DNSIncoming:
            ttl = 120
            generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)

            if service_state_change == r.ServiceStateChange.Updated:
                generated.add_answer_at_time(
                    r.DNSText(
                        service_name,
                        const._TYPE_TXT,
                        const._CLASS_IN | const._CLASS_UNIQUE,
                        ttl,
                        service_text,
                    ),
                    0,
                )
                return r.DNSIncoming(generated.packets()[0])

            if service_state_change == r.ServiceStateChange.Removed:
                ttl = 0

            generated.add_answer_at_time(
                r.DNSPointer(service_type, const._TYPE_PTR, const._CLASS_IN, ttl, service_name), 0
            )
            generated.add_answer_at_time(
                r.DNSService(
                    service_name,
                    const._TYPE_SRV,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    ttl,
                    0,
                    0,
                    80,
                    service_server,
                ),
                0,
            )
            generated.add_answer_at_time(
                r.DNSText(
                    service_name, const._TYPE_TXT, const._CLASS_IN | const._CLASS_UNIQUE, ttl, service_text
                ),
                0,
            )
            generated.add_answer_at_time(
                r.DNSAddress(
                    service_server,
                    const._TYPE_A,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    ttl,
                    socket.inet_aton(service_address),
                ),
                0,
            )

            return r.DNSIncoming(generated.packets()[0])

        def mock_split_incoming_msg(service_state_change: r.ServiceStateChange) -> r.DNSIncoming:
            """Mock an incoming message for the case where the packet is split."""
            ttl = 120
            generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
            generated.add_answer_at_time(
                r.DNSAddress(
                    service_server,
                    const._TYPE_A,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    ttl,
                    socket.inet_aton(service_address),
                ),
                0,
            )
            generated.add_answer_at_time(
                r.DNSService(
                    service_name,
                    const._TYPE_SRV,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    ttl,
                    0,
                    0,
                    80,
                    service_server,
                ),
                0,
            )
            return r.DNSIncoming(generated.packets()[0])

        service_name = 'name._type._tcp.local.'
        service_type = '_type._tcp.local.'
        service_server = 'ash-2.local.'
        service_text = b'path=/~paulsm/'
        service_address = '10.0.1.2'

        zeroconf = r.Zeroconf(interfaces=['127.0.0.1'])

        try:
            # service added
            _inject_response(zeroconf, mock_incoming_msg(r.ServiceStateChange.Added))
            dns_text = zeroconf.cache.get_by_details(service_name, const._TYPE_TXT, const._CLASS_IN)
            assert dns_text is not None
            assert cast(r.DNSText, dns_text).text == service_text  # service_text is b'path=/~paulsm/'
            all_dns_text = zeroconf.cache.get_all_by_details(service_name, const._TYPE_TXT, const._CLASS_IN)
            assert [dns_text] == all_dns_text

            # https://tools.ietf.org/html/rfc6762#section-10.2
            # Instead of merging this new record additively into the cache in addition
            # to any previous records with the same name, rrtype, and rrclass,
            # all old records with that name, rrtype, and rrclass that were received
            # more than one second ago are declared invalid,
            # and marked to expire from the cache in one second.
            time.sleep(1.1)

            # service updated. currently only text record can be updated
            service_text = b'path=/~humingchun/'
            _inject_response(zeroconf, mock_incoming_msg(r.ServiceStateChange.Updated))
            dns_text = zeroconf.cache.get_by_details(service_name, const._TYPE_TXT, const._CLASS_IN)
            assert dns_text is not None
            assert cast(r.DNSText, dns_text).text == service_text  # service_text is b'path=/~humingchun/'

            time.sleep(1.1)

            # The split message only has a SRV and A record.
            # This should not evict TXT records from the cache
            _inject_response(zeroconf, mock_split_incoming_msg(r.ServiceStateChange.Updated))
            time.sleep(1.1)
            dns_text = zeroconf.cache.get_by_details(service_name, const._TYPE_TXT, const._CLASS_IN)
            assert dns_text is not None
            assert cast(r.DNSText, dns_text).text == service_text  # service_text is b'path=/~humingchun/'

            # service removed
            _inject_response(zeroconf, mock_incoming_msg(r.ServiceStateChange.Removed))
            dns_text = zeroconf.cache.get_by_details(service_name, const._TYPE_TXT, const._CLASS_IN)
            assert dns_text is None

        finally:
            zeroconf.close()


def test_notify_listeners():
    """Test adding and removing notify listeners."""
    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])
    notify_called = 0

    class TestNotifyListener(r.NotifyListener):
        def notify_all(self):
            nonlocal notify_called
            notify_called += 1

    with pytest.raises(NotImplementedError):
        r.NotifyListener().notify_all()

    notify_listener = TestNotifyListener()

    zc.add_notify_listener(notify_listener)

    def on_service_state_change(zeroconf, service_type, state_change, name):
        """Dummy service callback."""

    # start a browser
    browser = ServiceBrowser(zc, "_http._tcp.local.", [on_service_state_change])
    browser.cancel()

    assert notify_called
    zc.remove_notify_listener(notify_listener)

    notify_called = 0
    # start a browser
    browser = ServiceBrowser(zc, "_http._tcp.local.", [on_service_state_change])
    browser.cancel()

    assert not notify_called

    zc.close()


def test_generate_service_query_set_qu_bit():
    """Test generate_service_query sets the QU bit."""

    zeroconf_registrar = Zeroconf(interfaces=['127.0.0.1'])
    desc = {'path': '/~paulsm/'}
    type_ = "._hap._tcp.local."
    registration_name = "this-host-is-not-used._hap._tcp.local."
    info = r.ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
    )
    out = zeroconf_registrar.generate_service_query(info)
    assert out.questions[0].unicast is True
    zeroconf_registrar.close()
