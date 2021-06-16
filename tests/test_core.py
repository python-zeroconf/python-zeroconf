#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf._core """

import asyncio
import itertools
import logging
import os
import pytest
import socket
import sys
import time
import unittest
import unittest.mock
from typing import cast

import zeroconf as r
from zeroconf import _core, const, ServiceBrowser, Zeroconf

from . import has_working_ipv6, _clear_cache, _inject_response

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
        zeroconf.notify_all()
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

    @unittest.skipIf(sys.platform == 'darwin', reason="apple_p2p failure path not testable on mac")
    def test_launch_and_close_apple_p2p_not_mac(self):
        with pytest.raises(RuntimeError):
            r.Zeroconf(apple_p2p=True)

    @unittest.skipIf(sys.platform != 'darwin', reason="apple_p2p happy path only testable on mac")
    def test_launch_and_close_apple_p2p_on_mac(self):
        rv = r.Zeroconf(apple_p2p=True)
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


def test_invalid_packets_ignored_and_does_not_cause_loop_exception():
    """Ensure an invalid packet cannot cause the loop to collapse."""
    zc = Zeroconf(interfaces=['127.0.0.1'])
    generated = r.DNSOutgoing(0)
    packet = generated.packets()[0]
    packet = packet[:8] + b'deadbeef' + packet[8:]
    parsed = r.DNSIncoming(packet)
    assert parsed.valid is False

    # Invalid Packet
    mock_out = unittest.mock.Mock()
    mock_out.packets = lambda: [packet]
    zc.send(mock_out)

    # Invalid oversized packet
    mock_out = unittest.mock.Mock()
    mock_out.packets = lambda: [packet * 1000]
    zc.send(mock_out)

    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    entry = r.DNSText(
        "didnotcrashincoming._crash._tcp.local.",
        const._TYPE_TXT,
        const._CLASS_IN | const._CLASS_UNIQUE,
        500,
        b'path=/~paulsm/',
    )
    assert isinstance(entry, r.DNSText)
    assert isinstance(entry, r.DNSRecord)
    assert isinstance(entry, r.DNSEntry)

    generated.add_answer_at_time(entry, 0)
    zc.send(generated)
    time.sleep(0.2)
    zc.close()
    assert zc.cache.get(entry) is not None


def test_goodbye_all_services():
    """Verify generating the goodbye query does not change with time."""
    zc = Zeroconf(interfaces=['127.0.0.1'])
    out = zc.generate_unregister_all_services()
    assert out is None
    type_ = "_http._tcp.local."
    registration_name = "xxxyyy.%s" % type_
    desc = {'path': '/~paulsm/'}
    info = r.ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
    )
    zc.registry.add(info)
    out = zc.generate_unregister_all_services()
    assert out is not None
    first_packet = out.packets()
    zc.registry.add(info)
    out2 = zc.generate_unregister_all_services()
    assert out2 is not None
    second_packet = out.packets()
    assert second_packet == first_packet

    # Verify the registery is empty
    out3 = zc.generate_unregister_all_services()
    assert out3 is None
    assert zc.registry.get_service_infos() == []

    zc.close()


def test_register_service_with_custom_ttl():
    """Test a registering a service with a custom ttl."""

    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])

    # start a browser
    type_ = "_homeassistant._tcp.local."
    name = "MyTestHome"
    info_service = r.ServiceInfo(
        type_,
        '%s.%s' % (name, type_),
        80,
        0,
        0,
        {'path': '/~paulsm/'},
        "ash-90.local.",
        addresses=[socket.inet_aton("10.0.1.2")],
    )

    zc.register_service(info_service, ttl=30)
    assert zc.cache.get(info_service.dns_pointer()).ttl == 30
    zc.close()


def test_get_service_info_failure_path():
    """Verify get_service_info return None when the underlying call returns False."""
    zc = Zeroconf(interfaces=['127.0.0.1'])
    assert zc.get_service_info("_neverused._tcp.local.", "xneverused._neverused._tcp.local.", 10) is None
    zc.close()


def test_sending_unicast():
    """Test sending unicast response."""
    zc = Zeroconf(interfaces=['127.0.0.1'])
    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    entry = r.DNSText(
        "didnotcrashincoming._crash._tcp.local.",
        const._TYPE_TXT,
        const._CLASS_IN | const._CLASS_UNIQUE,
        500,
        b'path=/~paulsm/',
    )
    generated.add_answer_at_time(entry, 0)
    zc.send(generated, "2001:db8::1", const._MDNS_PORT)  # https://www.iana.org/go/rfc3849
    time.sleep(0.2)
    assert zc.cache.get(entry) is None

    zc.send(generated, "198.51.100.0", const._MDNS_PORT)  # Documentation (TEST-NET-2)
    time.sleep(0.2)
    assert zc.cache.get(entry) is None

    zc.send(generated)
    time.sleep(0.2)
    assert zc.cache.get(entry) is not None

    zc.close()


def test_tc_bit_defers():
    zc = Zeroconf(interfaces=['127.0.0.1'])
    type_ = "_tcbitdefer._tcp.local."
    name = "knownname"
    name2 = "knownname2"
    name3 = "knownname3"

    registration_name = "%s.%s" % (name, type_)
    registration2_name = "%s.%s" % (name2, type_)
    registration3_name = "%s.%s" % (name3, type_)

    desc = {'path': '/~paulsm/'}
    server_name = "ash-2.local."
    server_name2 = "ash-3.local."
    server_name3 = "ash-4.local."

    info = r.ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, server_name, addresses=[socket.inet_aton("10.0.1.2")]
    )
    info2 = r.ServiceInfo(
        type_, registration2_name, 80, 0, 0, desc, server_name2, addresses=[socket.inet_aton("10.0.1.2")]
    )
    info3 = r.ServiceInfo(
        type_, registration3_name, 80, 0, 0, desc, server_name3, addresses=[socket.inet_aton("10.0.1.2")]
    )
    zc.registry.add(info)
    zc.registry.add(info2)
    zc.registry.add(info3)

    def threadsafe_query(*args):
        async def make_query():
            zc.handle_query(*args)

        asyncio.run_coroutine_threadsafe(make_query(), zc.loop).result()

    now = r.current_time_millis()
    _clear_cache(zc)

    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(type_, const._TYPE_PTR, const._CLASS_IN)
    generated.add_question(question)
    for _ in range(300):
        # Add so many answers we end up with another packet
        generated.add_answer_at_time(info.dns_pointer(), now)
    generated.add_answer_at_time(info2.dns_pointer(), now)
    generated.add_answer_at_time(info3.dns_pointer(), now)
    packets = generated.packets()
    assert len(packets) == 4
    expected_deferred = []
    source_ip = '203.0.113.13'

    next_packet = r.DNSIncoming(packets.pop(0))
    expected_deferred.append(next_packet)
    threadsafe_query(next_packet, source_ip, const._MDNS_PORT)
    assert zc._deferred[source_ip] == expected_deferred
    assert source_ip in zc._timers

    next_packet = r.DNSIncoming(packets.pop(0))
    expected_deferred.append(next_packet)
    threadsafe_query(next_packet, source_ip, const._MDNS_PORT)
    assert zc._deferred[source_ip] == expected_deferred
    assert source_ip in zc._timers
    threadsafe_query(next_packet, source_ip, const._MDNS_PORT)
    assert zc._deferred[source_ip] == expected_deferred
    assert source_ip in zc._timers

    next_packet = r.DNSIncoming(packets.pop(0))
    expected_deferred.append(next_packet)
    threadsafe_query(next_packet, source_ip, const._MDNS_PORT)
    assert zc._deferred[source_ip] == expected_deferred
    assert source_ip in zc._timers

    next_packet = r.DNSIncoming(packets.pop(0))
    expected_deferred.append(next_packet)
    threadsafe_query(next_packet, source_ip, const._MDNS_PORT)
    assert source_ip not in zc._deferred
    assert source_ip not in zc._timers

    # unregister
    zc.unregister_service(info)
    zc.close()


def test_tc_bit_defers_last_response_missing():
    zc = Zeroconf(interfaces=['127.0.0.1'])
    type_ = "_knowndefer._tcp.local."
    name = "knownname"
    name2 = "knownname2"
    name3 = "knownname3"

    registration_name = "%s.%s" % (name, type_)
    registration2_name = "%s.%s" % (name2, type_)
    registration3_name = "%s.%s" % (name3, type_)

    desc = {'path': '/~paulsm/'}
    server_name = "ash-2.local."
    server_name2 = "ash-3.local."
    server_name3 = "ash-4.local."

    info = r.ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, server_name, addresses=[socket.inet_aton("10.0.1.2")]
    )
    info2 = r.ServiceInfo(
        type_, registration2_name, 80, 0, 0, desc, server_name2, addresses=[socket.inet_aton("10.0.1.2")]
    )
    info3 = r.ServiceInfo(
        type_, registration3_name, 80, 0, 0, desc, server_name3, addresses=[socket.inet_aton("10.0.1.2")]
    )
    zc.registry.add(info)
    zc.registry.add(info2)
    zc.registry.add(info3)

    def threadsafe_query(*args):
        async def make_query():
            zc.handle_query(*args)

        asyncio.run_coroutine_threadsafe(make_query(), zc.loop).result()

    now = r.current_time_millis()
    _clear_cache(zc)
    source_ip = '203.0.113.12'

    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(type_, const._TYPE_PTR, const._CLASS_IN)
    generated.add_question(question)
    for _ in range(300):
        # Add so many answers we end up with another packet
        generated.add_answer_at_time(info.dns_pointer(), now)
    generated.add_answer_at_time(info2.dns_pointer(), now)
    generated.add_answer_at_time(info3.dns_pointer(), now)
    packets = generated.packets()
    assert len(packets) == 4
    expected_deferred = []

    next_packet = r.DNSIncoming(packets.pop(0))
    expected_deferred.append(next_packet)
    threadsafe_query(next_packet, source_ip, const._MDNS_PORT)
    assert zc._deferred[source_ip] == expected_deferred
    timer1 = zc._timers[source_ip]

    next_packet = r.DNSIncoming(packets.pop(0))
    expected_deferred.append(next_packet)
    threadsafe_query(next_packet, source_ip, const._MDNS_PORT)
    assert zc._deferred[source_ip] == expected_deferred
    timer2 = zc._timers[source_ip]
    if sys.version_info >= (3, 7):
        assert timer1.cancelled()
    assert timer2 != timer1

    # Send the same packet again to similar multi interfaces
    threadsafe_query(next_packet, source_ip, const._MDNS_PORT)
    assert zc._deferred[source_ip] == expected_deferred
    assert source_ip in zc._timers
    timer3 = zc._timers[source_ip]
    if sys.version_info >= (3, 7):
        assert not timer3.cancelled()
    assert timer3 == timer2

    next_packet = r.DNSIncoming(packets.pop(0))
    expected_deferred.append(next_packet)
    threadsafe_query(next_packet, source_ip, const._MDNS_PORT)
    assert zc._deferred[source_ip] == expected_deferred
    assert source_ip in zc._timers
    timer4 = zc._timers[source_ip]
    if sys.version_info >= (3, 7):
        assert timer3.cancelled()
    assert timer4 != timer3

    for _ in range(7):
        time.sleep(0.1)
        if source_ip not in zc._timers:
            break

    assert source_ip not in zc._deferred
    assert source_ip not in zc._timers

    # unregister
    zc.registry.remove(info)
    zc.close()
