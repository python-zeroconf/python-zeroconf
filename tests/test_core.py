#!/usr/bin/env python


""" Unit tests for zeroconf._core """

import asyncio
import itertools
import logging
import os
import socket
import sys
import threading
import time
import unittest
import unittest.mock
from typing import Set, cast
from unittest.mock import MagicMock, patch

import pytest

import zeroconf as r
from zeroconf import NotRunningException, Zeroconf, _core, const, current_time_millis
from zeroconf._protocol import outgoing
from zeroconf.asyncio import AsyncZeroconf

from . import _clear_cache, _inject_response, _wait_for_start, has_working_ipv6

log = logging.getLogger('zeroconf')
original_logging_level = logging.NOTSET


def setup_module():
    global original_logging_level
    original_logging_level = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    if original_logging_level != logging.NOTSET:
        log.setLevel(original_logging_level)


def threadsafe_query(zc, protocol, *args):
    async def make_query():
        protocol.handle_query_or_defer(*args)

    asyncio.run_coroutine_threadsafe(make_query(), zc.loop).result()


# This test uses asyncio because it needs to access the cache directly
# which is not threadsafe
@pytest.mark.asyncio
async def test_reaper():
    with patch.object(_core, "_CACHE_CLEANUP_INTERVAL", 0.01):
        aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
        zeroconf = aiozc.zeroconf
        cache = zeroconf.cache
        original_entries = list(itertools.chain(*(cache.entries_with_name(name) for name in cache.names())))
        record_with_10s_ttl = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 10, b'a')
        record_with_1s_ttl = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'b')
        zeroconf.cache.async_add_records([record_with_10s_ttl, record_with_1s_ttl])
        question = r.DNSQuestion("_hap._tcp._local.", const._TYPE_PTR, const._CLASS_IN)
        now = r.current_time_millis()
        other_known_answers: Set[r.DNSRecord] = {
            r.DNSPointer(
                "_hap._tcp.local.",
                const._TYPE_PTR,
                const._CLASS_IN,
                10000,
                'known-to-other._hap._tcp.local.',
            )
        }
        zeroconf.question_history.add_question_at_time(question, now, other_known_answers)
        assert zeroconf.question_history.suppresses(question, now, other_known_answers)
        entries_with_cache = list(itertools.chain(*(cache.entries_with_name(name) for name in cache.names())))
        await asyncio.sleep(1.2)
        entries = list(itertools.chain(*(cache.entries_with_name(name) for name in cache.names())))
        assert zeroconf.cache.get(record_with_1s_ttl) is None
        await aiozc.async_close()
        assert not zeroconf.question_history.suppresses(question, now, other_known_answers)
        assert entries != original_entries
        assert entries_with_cache != original_entries
        assert record_with_10s_ttl in entries
        assert record_with_1s_ttl not in entries


@pytest.mark.asyncio
async def test_reaper_aborts_when_done():
    """Ensure cache cleanup stops when zeroconf is done."""
    with patch.object(_core, "_CACHE_CLEANUP_INTERVAL", 0.01):
        aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
        zeroconf = aiozc.zeroconf
        record_with_10s_ttl = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 10, b'a')
        record_with_1s_ttl = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'b')
        zeroconf.cache.async_add_records([record_with_10s_ttl, record_with_1s_ttl])
        assert zeroconf.cache.get(record_with_10s_ttl) is not None
        assert zeroconf.cache.get(record_with_1s_ttl) is not None
        await aiozc.async_close()
        await asyncio.sleep(1.2)
        assert zeroconf.cache.get(record_with_10s_ttl) is not None
        assert zeroconf.cache.get(record_with_1s_ttl) is not None


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

        with r.Zeroconf(interfaces=r.InterfaceChoice.Default) as rv:  # type: ignore[unreachable]
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
            assert dns_text is not None
            assert dns_text.is_expired(current_time_millis() + 1000)

        finally:
            zeroconf.close()


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
    zc.registry.async_add(info)
    out = zc.generate_unregister_all_services()
    assert out is not None
    first_packet = out.packets()
    zc.registry.async_add(info)
    out2 = zc.generate_unregister_all_services()
    assert out2 is not None
    second_packet = out.packets()
    assert second_packet == first_packet

    # Verify the registery is empty
    out3 = zc.generate_unregister_all_services()
    assert out3 is None
    assert zc.registry.async_get_service_infos() == []

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
        f'{name}.{type_}',
        80,
        0,
        0,
        {'path': '/~paulsm/'},
        "ash-90.local.",
        addresses=[socket.inet_aton("10.0.1.2")],
    )

    zc.register_service(info_service, ttl=3000)
    record = zc.cache.get(info_service.dns_pointer())
    assert record is not None
    assert record.ttl == 3000
    zc.close()


def test_logging_packets(caplog):
    """Test packets are only logged with debug logging."""

    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])

    # start a browser
    type_ = "_logging._tcp.local."
    name = "TLD"
    info_service = r.ServiceInfo(
        type_,
        f'{name}.{type_}',
        80,
        0,
        0,
        {'path': '/~paulsm/'},
        "ash-90.local.",
        addresses=[socket.inet_aton("10.0.1.2")],
    )

    logging.getLogger('zeroconf').setLevel(logging.DEBUG)
    caplog.clear()
    zc.register_service(info_service, ttl=3000)
    assert "Sending to" in caplog.text
    record = zc.cache.get(info_service.dns_pointer())
    assert record is not None
    assert record.ttl == 3000
    logging.getLogger('zeroconf').setLevel(logging.INFO)
    caplog.clear()
    zc.unregister_service(info_service)
    assert "Sending to" not in caplog.text
    logging.getLogger('zeroconf').setLevel(logging.DEBUG)

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

    # Handle slow github CI runners on windows
    for _ in range(10):
        time.sleep(0.05)
        if zc.cache.get(entry) is not None:
            break

    assert zc.cache.get(entry) is not None

    zc.close()


def test_tc_bit_defers():
    zc = Zeroconf(interfaces=['127.0.0.1'])
    _wait_for_start(zc)
    type_ = "_tcbitdefer._tcp.local."
    name = "knownname"
    name2 = "knownname2"
    name3 = "knownname3"

    registration_name = f"{name}.{type_}"
    registration2_name = f"{name2}.{type_}"
    registration3_name = f"{name3}.{type_}"

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
    zc.registry.async_add(info)
    zc.registry.async_add(info2)
    zc.registry.async_add(info3)

    protocol = zc.engine.protocols[0]
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
    threadsafe_query(zc, protocol, next_packet, source_ip, const._MDNS_PORT, None)
    assert protocol._deferred[source_ip] == expected_deferred
    assert source_ip in protocol._timers

    next_packet = r.DNSIncoming(packets.pop(0))
    expected_deferred.append(next_packet)
    threadsafe_query(zc, protocol, next_packet, source_ip, const._MDNS_PORT, None)
    assert protocol._deferred[source_ip] == expected_deferred
    assert source_ip in protocol._timers
    threadsafe_query(zc, protocol, next_packet, source_ip, const._MDNS_PORT, None)
    assert protocol._deferred[source_ip] == expected_deferred
    assert source_ip in protocol._timers

    next_packet = r.DNSIncoming(packets.pop(0))
    expected_deferred.append(next_packet)
    threadsafe_query(zc, protocol, next_packet, source_ip, const._MDNS_PORT, None)
    assert protocol._deferred[source_ip] == expected_deferred
    assert source_ip in protocol._timers

    next_packet = r.DNSIncoming(packets.pop(0))
    expected_deferred.append(next_packet)
    threadsafe_query(zc, protocol, next_packet, source_ip, const._MDNS_PORT, None)
    assert source_ip not in protocol._deferred
    assert source_ip not in protocol._timers

    # unregister
    zc.unregister_service(info)
    zc.close()


def test_tc_bit_defers_last_response_missing():
    zc = Zeroconf(interfaces=['127.0.0.1'])
    _wait_for_start(zc)
    type_ = "_knowndefer._tcp.local."
    name = "knownname"
    name2 = "knownname2"
    name3 = "knownname3"

    registration_name = f"{name}.{type_}"
    registration2_name = f"{name2}.{type_}"
    registration3_name = f"{name3}.{type_}"

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
    zc.registry.async_add(info)
    zc.registry.async_add(info2)
    zc.registry.async_add(info3)

    protocol = zc.engine.protocols[0]
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
    threadsafe_query(zc, protocol, next_packet, source_ip, const._MDNS_PORT, None)
    assert protocol._deferred[source_ip] == expected_deferred
    timer1 = protocol._timers[source_ip]

    next_packet = r.DNSIncoming(packets.pop(0))
    expected_deferred.append(next_packet)
    threadsafe_query(zc, protocol, next_packet, source_ip, const._MDNS_PORT, None)
    assert protocol._deferred[source_ip] == expected_deferred
    timer2 = protocol._timers[source_ip]
    assert timer1.cancelled()
    assert timer2 != timer1

    # Send the same packet again to similar multi interfaces
    threadsafe_query(zc, protocol, next_packet, source_ip, const._MDNS_PORT, None)
    assert protocol._deferred[source_ip] == expected_deferred
    assert source_ip in protocol._timers
    timer3 = protocol._timers[source_ip]
    assert not timer3.cancelled()
    assert timer3 == timer2

    next_packet = r.DNSIncoming(packets.pop(0))
    expected_deferred.append(next_packet)
    threadsafe_query(zc, protocol, next_packet, source_ip, const._MDNS_PORT, None)
    assert protocol._deferred[source_ip] == expected_deferred
    assert source_ip in protocol._timers
    timer4 = protocol._timers[source_ip]
    assert timer3.cancelled()
    assert timer4 != timer3

    for _ in range(8):
        time.sleep(0.1)
        if source_ip not in protocol._timers and source_ip not in protocol._deferred:
            break

    assert source_ip not in protocol._deferred
    assert source_ip not in protocol._timers

    # unregister
    zc.registry.async_remove(info)
    zc.close()


@pytest.mark.asyncio
async def test_open_close_twice_from_async() -> None:
    """Test we can close twice from a coroutine when using Zeroconf.

    Ideally callers switch to using AsyncZeroconf, however there will
    be a peroid where they still call the sync wrapper that we want
    to ensure will not deadlock on shutdown.

    This test is expected to throw warnings about tasks being destroyed
    since we force shutdown right away since we don't want to block
    callers event loops and since they aren't using the AsyncZeroconf
    version they won't yield with an await like async_close we don't
    have much choice but to force things down.
    """
    zc = Zeroconf(interfaces=['127.0.0.1'])
    zc.close()
    zc.close()
    await asyncio.sleep(0)


@pytest.mark.asyncio
async def test_multiple_sync_instances_stared_from_async_close():
    """Test we can shutdown multiple sync instances from async."""

    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])
    zc2 = Zeroconf(interfaces=['127.0.0.1'])
    assert zc.loop is not None
    assert zc2.loop is not None

    assert zc.loop == zc2.loop
    zc.close()
    assert zc.loop.is_running()
    zc2.close()
    assert zc2.loop.is_running()

    zc3 = Zeroconf(interfaces=['127.0.0.1'])
    assert zc3.loop == zc2.loop

    zc3.close()
    assert zc3.loop.is_running()

    await asyncio.sleep(0)


def test_guard_against_oversized_packets():
    """Ensure we do not process oversized packets.

    These packets can quickly overwhelm the system.
    """
    zc = Zeroconf(interfaces=['127.0.0.1'])

    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)

    for i in range(5000):
        generated.add_answer_at_time(
            r.DNSText(
                "packet{i}.local.",
                const._TYPE_TXT,
                const._CLASS_IN | const._CLASS_UNIQUE,
                500,
                b'path=/~paulsm/',
            ),
            0,
        )

    try:
        # We are patching to generate an oversized packet
        with patch.object(outgoing, "_MAX_MSG_ABSOLUTE", 100000), patch.object(
            outgoing, "_MAX_MSG_TYPICAL", 100000
        ):
            over_sized_packet = generated.packets()[0]
            assert len(over_sized_packet) > const._MAX_MSG_ABSOLUTE
    except AttributeError:
        # cannot patch with cython
        zc.close()
        return

    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    okpacket_record = r.DNSText(
        "okpacket.local.",
        const._TYPE_TXT,
        const._CLASS_IN | const._CLASS_UNIQUE,
        500,
        b'path=/~paulsm/',
    )

    generated.add_answer_at_time(
        okpacket_record,
        0,
    )
    ok_packet = generated.packets()[0]

    # We cannot test though the network interface as some operating systems
    # will guard against the oversized packet and we won't see it.
    listener = _core.AsyncListener(zc)
    listener.transport = unittest.mock.MagicMock()

    listener.datagram_received(ok_packet, ('127.0.0.1', const._MDNS_PORT))
    assert zc.cache.async_get_unique(okpacket_record) is not None

    listener.datagram_received(over_sized_packet, ('127.0.0.1', const._MDNS_PORT))
    assert (
        zc.cache.async_get_unique(
            r.DNSText(
                "packet0.local.",
                const._TYPE_TXT,
                const._CLASS_IN | const._CLASS_UNIQUE,
                500,
                b'path=/~paulsm/',
            )
        )
        is None
    )

    logging.getLogger('zeroconf').setLevel(logging.INFO)

    listener.datagram_received(over_sized_packet, ('::1', const._MDNS_PORT, 1, 1))
    assert (
        zc.cache.async_get_unique(
            r.DNSText(
                "packet0.local.",
                const._TYPE_TXT,
                const._CLASS_IN | const._CLASS_UNIQUE,
                500,
                b'path=/~paulsm/',
            )
        )
        is None
    )

    zc.close()


def test_guard_against_duplicate_packets():
    """Ensure we do not process duplicate packets.
    These packets can quickly overwhelm the system.
    """
    zc = Zeroconf(interfaces=['127.0.0.1'])
    listener = _core.AsyncListener(zc)
    listener.transport = MagicMock()

    query = r.DNSOutgoing(const._FLAGS_QR_QUERY, multicast=True)
    question = r.DNSQuestion("x._http._tcp.local.", const._TYPE_PTR, const._CLASS_IN)
    query.add_question(question)
    packet_with_qm_question = query.packets()[0]

    query3 = r.DNSOutgoing(const._FLAGS_QR_QUERY, multicast=True)
    question3 = r.DNSQuestion("x._ay._tcp.local.", const._TYPE_PTR, const._CLASS_IN)
    query3.add_question(question3)
    packet_with_qm_question2 = query3.packets()[0]

    query2 = r.DNSOutgoing(const._FLAGS_QR_QUERY, multicast=True)
    question2 = r.DNSQuestion("x._http._tcp.local.", const._TYPE_PTR, const._CLASS_IN)
    question2.unicast = True
    query2.add_question(question2)
    packet_with_qu_question = query2.packets()[0]

    addrs = ("1.2.3.4", 43)

    with patch.object(_core, "current_time_millis") as _current_time_millis, patch.object(
        listener, "handle_query_or_defer"
    ) as _handle_query_or_defer:
        start_time = current_time_millis()

        _current_time_millis.return_value = start_time
        listener.datagram_received(packet_with_qm_question, addrs)
        _handle_query_or_defer.assert_called_once()
        _handle_query_or_defer.reset_mock()

        # Now call with the same packet again and handle_query_or_defer should not fire
        listener.datagram_received(packet_with_qm_question, addrs)
        _handle_query_or_defer.assert_not_called()
        _handle_query_or_defer.reset_mock()

        # Now walk time forward 1000 seconds
        _current_time_millis.return_value = start_time + 1000
        # Now call with the same packet again and handle_query_or_defer should fire
        listener.datagram_received(packet_with_qm_question, addrs)
        _handle_query_or_defer.assert_called_once()
        _handle_query_or_defer.reset_mock()

        # Now call with the different packet and handle_query_or_defer should fire
        listener.datagram_received(packet_with_qm_question2, addrs)
        _handle_query_or_defer.assert_called_once()
        _handle_query_or_defer.reset_mock()

        # Now call with the different packet and handle_query_or_defer should fire
        listener.datagram_received(packet_with_qm_question, addrs)
        _handle_query_or_defer.assert_called_once()
        _handle_query_or_defer.reset_mock()

        # Now call with the different packet with qu question and handle_query_or_defer should fire
        listener.datagram_received(packet_with_qu_question, addrs)
        _handle_query_or_defer.assert_called_once()
        _handle_query_or_defer.reset_mock()

        # Now call again with the same packet that has a qu question and handle_query_or_defer should fire
        listener.datagram_received(packet_with_qu_question, addrs)
        _handle_query_or_defer.assert_called_once()
        _handle_query_or_defer.reset_mock()

        log.setLevel(logging.WARNING)

        # Call with the QM packet again
        listener.datagram_received(packet_with_qm_question, addrs)
        _handle_query_or_defer.assert_called_once()
        _handle_query_or_defer.reset_mock()

        # Now call with the same packet again and handle_query_or_defer should not fire
        listener.datagram_received(packet_with_qm_question, addrs)
        _handle_query_or_defer.assert_not_called()
        _handle_query_or_defer.reset_mock()

        # Now call with garbage
        listener.datagram_received(b'garbage', addrs)
        _handle_query_or_defer.assert_not_called()
        _handle_query_or_defer.reset_mock()

    zc.close()


def test_shutdown_while_register_in_process():
    """Test we can shutdown while registering a service in another thread."""

    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])

    # start a browser
    type_ = "_homeassistant._tcp.local."
    name = "MyTestHome"
    info_service = r.ServiceInfo(
        type_,
        f'{name}.{type_}',
        80,
        0,
        0,
        {'path': '/~paulsm/'},
        "ash-90.local.",
        addresses=[socket.inet_aton("10.0.1.2")],
    )

    def _background_register():
        zc.register_service(info_service)

    bgthread = threading.Thread(target=_background_register, daemon=True)
    bgthread.start()
    time.sleep(0.3)

    zc.close()
    bgthread.join()


@pytest.mark.asyncio
@unittest.skipIf(sys.version_info[:3][1] < 8, 'Requires Python 3.8 or later to patch _async_setup')
@patch("zeroconf._core._STARTUP_TIMEOUT", 0)
@patch("zeroconf._core.AsyncEngine._async_setup")
async def test_event_loop_blocked(mock_start):
    """Test we raise NotRunningException when waiting for startup that times out."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    with pytest.raises(NotRunningException):
        await aiozc.zeroconf.async_wait_for_start()
    assert aiozc.zeroconf.started is False
