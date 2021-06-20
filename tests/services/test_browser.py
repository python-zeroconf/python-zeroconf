#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf._services.browser. """

import logging
import socket
import time
import os
import unittest
from threading import Event

import pytest

import zeroconf as r
from zeroconf import DNSPointer, DNSQuestion, const, current_time_millis
import zeroconf._services.browser as _services_browser
from zeroconf import Zeroconf
from zeroconf._services import ServiceStateChange
from zeroconf._services.browser import ServiceBrowser
from zeroconf._services.info import ServiceInfo

from .. import has_working_ipv6, _inject_response


log = logging.getLogger('zeroconf')
original_logging_level = logging.NOTSET


def setup_module():
    global original_logging_level
    original_logging_level = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    if original_logging_level != logging.NOTSET:
        log.setLevel(original_logging_level)


def test_service_browser_cancel_multiple_times():
    """Test we can cancel a ServiceBrowser multiple times before close."""

    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])
    # start a browser
    type_ = "_hap._tcp.local."

    class MyServiceListener(r.ServiceListener):
        pass

    listener = MyServiceListener()

    browser = r.ServiceBrowser(zc, type_, None, listener)

    browser.cancel()
    browser.cancel()
    browser.cancel()

    zc.close()


def test_service_browser_cancel_multiple_times_after_close():
    """Test we can cancel a ServiceBrowser multiple times after close."""

    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])
    # start a browser
    type_ = "_hap._tcp.local."

    class MyServiceListener(r.ServiceListener):
        pass

    listener = MyServiceListener()

    browser = r.ServiceBrowser(zc, type_, None, listener)

    zc.close()

    browser.cancel()
    browser.cancel()
    browser.cancel()


def test_service_browser_started_after_zeroconf_closed():
    """Test starting a ServiceBrowser after close raises RuntimeError."""
    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])
    # start a browser
    type_ = "_hap._tcp.local."

    class MyServiceListener(r.ServiceListener):
        pass

    listener = MyServiceListener()
    zc.close()

    with pytest.raises(RuntimeError):
        browser = r.ServiceBrowser(zc, type_, None, listener)


def test_multiple_instances_running_close():
    """Test we can shutdown multiple instances."""

    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])
    zc2 = Zeroconf(interfaces=['127.0.0.1'])
    zc3 = Zeroconf(interfaces=['127.0.0.1'])

    assert zc.loop != zc2.loop
    assert zc.loop != zc3.loop

    class MyServiceListener(r.ServiceListener):
        pass

    listener = MyServiceListener()

    zc2.add_service_listener("zca._hap._tcp.local.", listener)

    zc.close()
    zc2.remove_service_listener(listener)
    zc2.close()
    zc3.close()


class TestServiceBrowser(unittest.TestCase):
    def test_update_record(self):
        enable_ipv6 = has_working_ipv6() and not os.environ.get('SKIP_IPV6')

        service_name = 'name._type._tcp.local.'
        service_type = '_type._tcp.local.'
        service_server = 'ash-1.local.'
        service_text = b'path=/~matt1/'
        service_address = '10.0.1.2'
        service_v6_address = "2001:db8::1"
        service_v6_second_address = "6001:db8::1"

        service_added_count = 0
        service_removed_count = 0
        service_updated_count = 0
        service_add_event = Event()
        service_removed_event = Event()
        service_updated_event = Event()

        class MyServiceListener(r.ServiceListener):
            def add_service(self, zc, type_, name) -> None:
                nonlocal service_added_count
                service_added_count += 1
                service_add_event.set()

            def remove_service(self, zc, type_, name) -> None:
                nonlocal service_removed_count
                service_removed_count += 1
                service_removed_event.set()

            def update_service(self, zc, type_, name) -> None:
                nonlocal service_updated_count
                service_updated_count += 1
                service_info = zc.get_service_info(type_, name)
                assert socket.inet_aton(service_address) in service_info.addresses
                if enable_ipv6:
                    assert socket.inet_pton(
                        socket.AF_INET6, service_v6_address
                    ) in service_info.addresses_by_version(r.IPVersion.V6Only)
                    assert socket.inet_pton(
                        socket.AF_INET6, service_v6_second_address
                    ) in service_info.addresses_by_version(r.IPVersion.V6Only)
                assert service_info.text == service_text
                assert service_info.server == service_server
                service_updated_event.set()

        def mock_incoming_msg(service_state_change: r.ServiceStateChange) -> r.DNSIncoming:

            generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
            assert generated.is_response() is True

            if service_state_change == r.ServiceStateChange.Removed:
                ttl = 0
            else:
                ttl = 120

            generated.add_answer_at_time(
                r.DNSText(
                    service_name, const._TYPE_TXT, const._CLASS_IN | const._CLASS_UNIQUE, ttl, service_text
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

            # Send the IPv6 address first since we previously
            # had a bug where the IPv4 would be missing if the
            # IPv6 was seen first
            if enable_ipv6:
                generated.add_answer_at_time(
                    r.DNSAddress(
                        service_server,
                        const._TYPE_AAAA,
                        const._CLASS_IN | const._CLASS_UNIQUE,
                        ttl,
                        socket.inet_pton(socket.AF_INET6, service_v6_address),
                    ),
                    0,
                )
                generated.add_answer_at_time(
                    r.DNSAddress(
                        service_server,
                        const._TYPE_AAAA,
                        const._CLASS_IN | const._CLASS_UNIQUE,
                        ttl,
                        socket.inet_pton(socket.AF_INET6, service_v6_second_address),
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

            generated.add_answer_at_time(
                r.DNSPointer(service_type, const._TYPE_PTR, const._CLASS_IN, ttl, service_name), 0
            )

            return r.DNSIncoming(generated.packets()[0])

        zeroconf = r.Zeroconf(interfaces=['127.0.0.1'])
        service_browser = r.ServiceBrowser(zeroconf, service_type, listener=MyServiceListener())

        try:
            wait_time = 3

            # service added
            _inject_response(zeroconf, mock_incoming_msg(r.ServiceStateChange.Added))
            service_add_event.wait(wait_time)
            assert service_added_count == 1
            assert service_updated_count == 0
            assert service_removed_count == 0

            # service SRV updated
            service_updated_event.clear()
            service_server = 'ash-2.local.'
            _inject_response(zeroconf, mock_incoming_msg(r.ServiceStateChange.Updated))
            service_updated_event.wait(wait_time)
            assert service_added_count == 1
            assert service_updated_count == 1
            assert service_removed_count == 0

            # service TXT updated
            service_updated_event.clear()
            service_text = b'path=/~matt2/'
            _inject_response(zeroconf, mock_incoming_msg(r.ServiceStateChange.Updated))
            service_updated_event.wait(wait_time)
            assert service_added_count == 1
            assert service_updated_count == 2
            assert service_removed_count == 0

            # service TXT updated - duplicate update should not trigger another service_updated
            service_updated_event.clear()
            service_text = b'path=/~matt2/'
            _inject_response(zeroconf, mock_incoming_msg(r.ServiceStateChange.Updated))
            service_updated_event.wait(wait_time)
            assert service_added_count == 1
            assert service_updated_count == 2
            assert service_removed_count == 0

            # service A updated
            service_updated_event.clear()
            service_address = '10.0.1.3'
            # Verify we match on uppercase
            service_server = service_server.upper()
            _inject_response(zeroconf, mock_incoming_msg(r.ServiceStateChange.Updated))
            service_updated_event.wait(wait_time)
            assert service_added_count == 1
            assert service_updated_count == 3
            assert service_removed_count == 0

            # service all updated
            service_updated_event.clear()
            service_server = 'ash-3.local.'
            service_text = b'path=/~matt3/'
            service_address = '10.0.1.3'
            _inject_response(zeroconf, mock_incoming_msg(r.ServiceStateChange.Updated))
            service_updated_event.wait(wait_time)
            assert service_added_count == 1
            assert service_updated_count == 4
            assert service_removed_count == 0

            # service removed
            _inject_response(zeroconf, mock_incoming_msg(r.ServiceStateChange.Removed))
            service_removed_event.wait(wait_time)
            assert service_added_count == 1
            assert service_updated_count == 4
            assert service_removed_count == 1

        finally:
            assert len(zeroconf.listeners) == 1
            service_browser.cancel()
            assert len(zeroconf.listeners) == 0
            zeroconf.remove_all_service_listeners()
            zeroconf.close()


class TestServiceBrowserMultipleTypes(unittest.TestCase):
    def test_update_record(self):

        service_names = ['name2._type2._tcp.local.', 'name._type._tcp.local.', 'name._type._udp.local']
        service_types = ['_type2._tcp.local.', '_type._tcp.local.', '_type._udp.local.']

        service_added_count = 0
        service_removed_count = 0
        service_add_event = Event()
        service_removed_event = Event()

        class MyServiceListener(r.ServiceListener):
            def add_service(self, zc, type_, name) -> None:
                nonlocal service_added_count
                service_added_count += 1
                if service_added_count == 3:
                    service_add_event.set()

            def remove_service(self, zc, type_, name) -> None:
                nonlocal service_removed_count
                service_removed_count += 1
                if service_removed_count == 3:
                    service_removed_event.set()

        def mock_incoming_msg(
            service_state_change: r.ServiceStateChange, service_type: str, service_name: str, ttl: int
        ) -> r.DNSIncoming:
            generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
            generated.add_answer_at_time(
                r.DNSPointer(service_type, const._TYPE_PTR, const._CLASS_IN, ttl, service_name), 0
            )
            return r.DNSIncoming(generated.packets()[0])

        zeroconf = r.Zeroconf(interfaces=['127.0.0.1'])
        service_browser = r.ServiceBrowser(zeroconf, service_types, listener=MyServiceListener())

        try:
            wait_time = 3

            # all three services added
            _inject_response(
                zeroconf,
                mock_incoming_msg(r.ServiceStateChange.Added, service_types[0], service_names[0], 120),
            )
            _inject_response(
                zeroconf,
                mock_incoming_msg(r.ServiceStateChange.Added, service_types[1], service_names[1], 120),
            )
            zeroconf.wait(100)

            called_with_refresh_time_check = False

            def _mock_get_expiration_time(self, percent):
                nonlocal called_with_refresh_time_check
                if percent == const._EXPIRE_REFRESH_TIME_PERCENT:
                    called_with_refresh_time_check = True
                    return 0
                return self.created + (percent * self.ttl * 10)

            # Set an expire time that will force a refresh
            with unittest.mock.patch("zeroconf.DNSRecord.get_expiration_time", new=_mock_get_expiration_time):
                _inject_response(
                    zeroconf,
                    mock_incoming_msg(r.ServiceStateChange.Added, service_types[0], service_names[0], 120),
                )
                # Add the last record after updating the first one
                # to ensure the service_add_event only gets set
                # after the update
                _inject_response(
                    zeroconf,
                    mock_incoming_msg(r.ServiceStateChange.Added, service_types[2], service_names[2], 120),
                )
                service_add_event.wait(wait_time)
            assert called_with_refresh_time_check is True
            assert service_added_count == 3
            assert service_removed_count == 0

            _inject_response(
                zeroconf,
                mock_incoming_msg(r.ServiceStateChange.Updated, service_types[0], service_names[0], 0),
            )

            # all three services removed
            _inject_response(
                zeroconf,
                mock_incoming_msg(r.ServiceStateChange.Removed, service_types[0], service_names[0], 0),
            )
            _inject_response(
                zeroconf,
                mock_incoming_msg(r.ServiceStateChange.Removed, service_types[1], service_names[1], 0),
            )
            _inject_response(
                zeroconf,
                mock_incoming_msg(r.ServiceStateChange.Removed, service_types[2], service_names[2], 0),
            )
            service_removed_event.wait(wait_time)
            assert service_added_count == 3
            assert service_removed_count == 3

        finally:
            assert len(zeroconf.listeners) == 1
            service_browser.cancel()
            assert len(zeroconf.listeners) == 0
            zeroconf.remove_all_service_listeners()
            zeroconf.close()


def test_backoff():
    got_query = Event()

    type_ = "_http._tcp.local."
    zeroconf_browser = Zeroconf(interfaces=['127.0.0.1'])

    # we are going to patch the zeroconf send to check query transmission
    old_send = zeroconf_browser.async_send

    time_offset = 0.0
    start_time = time.time() * 1000
    initial_query_interval = _services_browser._BROWSER_TIME / 1000

    def current_time_millis():
        """Current system time in milliseconds"""
        return start_time + time_offset * 1000

    def send(out, addr=const._MDNS_ADDR, port=const._MDNS_PORT):
        """Sends an outgoing packet."""
        got_query.set()
        old_send(out, addr=addr, port=port)

    # patch the zeroconf send
    # patch the zeroconf current_time_millis
    # patch the backoff limit to prevent test running forever
    with unittest.mock.patch.object(zeroconf_browser, "async_send", send), unittest.mock.patch.object(
        _services_browser, "current_time_millis", current_time_millis
    ), unittest.mock.patch.object(_services_browser, "_BROWSER_BACKOFF_LIMIT", 10):
        # dummy service callback
        def on_service_state_change(zeroconf, service_type, state_change, name):
            pass

        browser = ServiceBrowser(zeroconf_browser, type_, [on_service_state_change])

        try:
            # Test that queries are sent at increasing intervals
            sleep_count = 0
            next_query_interval = 0.0
            expected_query_time = 0.0
            while True:
                sleep_count += 1
                for _ in range(2):
                    # If the browser thread is starting up
                    # its possible we notify before the initial sleep
                    # which means the test will fail so we need to d
                    # this twice to eliminate the race condition
                    zeroconf_browser.notify_all()
                    got_query.wait(0.05)
                if time_offset == expected_query_time:
                    assert got_query.is_set()
                    got_query.clear()
                    if next_query_interval == _services_browser._BROWSER_BACKOFF_LIMIT:
                        # Only need to test up to the point where we've seen a query
                        # after the backoff limit has been hit
                        break
                    elif next_query_interval == 0:
                        next_query_interval = initial_query_interval
                        expected_query_time = initial_query_interval
                    else:
                        next_query_interval = min(
                            2 * next_query_interval, _services_browser._BROWSER_BACKOFF_LIMIT
                        )
                        expected_query_time += next_query_interval
                else:
                    assert not got_query.is_set()
                time_offset += initial_query_interval

        finally:
            browser.cancel()
            zeroconf_browser.close()


def test_integration():
    service_added = Event()
    service_removed = Event()
    unexpected_ttl = Event()
    got_query = Event()

    type_ = "_http._tcp.local."
    registration_name = "xxxyyy.%s" % type_

    def on_service_state_change(zeroconf, service_type, state_change, name):
        if name == registration_name:
            if state_change is ServiceStateChange.Added:
                service_added.set()
            elif state_change is ServiceStateChange.Removed:
                service_removed.set()

    zeroconf_browser = Zeroconf(interfaces=['127.0.0.1'])

    # we are going to patch the zeroconf send to check packet sizes
    old_send = zeroconf_browser.async_send

    time_offset = 0.0

    def current_time_millis():
        """Current system time in milliseconds"""
        return time.time() * 1000 + time_offset * 1000

    expected_ttl = const._DNS_HOST_TTL
    was_set = False
    nbr_answers = 0

    def send(out, addr=const._MDNS_ADDR, port=const._MDNS_PORT):
        """Sends an outgoing packet."""
        nonlocal was_set
        pout = r.DNSIncoming(out.packets()[0])
        nonlocal nbr_answers
        for answer in pout.answers:
            nbr_answers += 1
            if not answer.ttl > expected_ttl / 2:
                unexpected_ttl.set()

        was_set = got_query.is_set()
        got_query.set()
        got_query.clear()

        old_send(out, addr=addr, port=port)

    # patch the zeroconf send
    # patch the zeroconf current_time_millis
    # patch the backoff limit to ensure we always get one query every 1/4 of the DNS TTL
    with unittest.mock.patch.object(zeroconf_browser, "async_send", send), unittest.mock.patch.object(
        _services_browser, "current_time_millis", current_time_millis
    ), unittest.mock.patch.object(_services_browser, "_BROWSER_BACKOFF_LIMIT", int(expected_ttl / 4)):
        service_added = Event()
        service_removed = Event()

        browser = ServiceBrowser(zeroconf_browser, type_, [on_service_state_change])

        zeroconf_registrar = Zeroconf(interfaces=['127.0.0.1'])
        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
        )
        zeroconf_registrar.register_service(info)

        try:
            service_added.wait(1)
            assert service_added.is_set()

            # Test that we receive queries containing answers only if the remaining TTL
            # is greater than half the original TTL
            sleep_count = 0
            test_iterations = 50

            while nbr_answers < test_iterations:
                # Increase simulated time shift by 1/4 of the TTL in seconds
                time_offset += expected_ttl / 4
                zeroconf_browser.notify_all()
                sleep_count += 1
                got_query.wait(0.1)
                # Prevent the test running indefinitely in an error condition
                assert sleep_count < test_iterations * 4
            assert not unexpected_ttl.is_set()

            # Don't remove service, allow close() to cleanup

        finally:
            zeroconf_registrar.close()
            service_removed.wait(1)
            assert service_removed.is_set()
            browser.cancel()
            zeroconf_browser.close()


def test_legacy_record_update_listener():
    """Test a RecordUpdateListener that does not implement update_records."""

    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])

    with pytest.raises(RuntimeError):
        r.RecordUpdateListener().update_record(
            zc, 0, r.DNSRecord('irrelevant', const._TYPE_SRV, const._CLASS_IN, const._DNS_HOST_TTL)
        )

    updates = []

    class LegacyRecordUpdateListener(r.RecordUpdateListener):
        """A RecordUpdateListener that does not implement update_records."""

        def update_record(self, zc: 'Zeroconf', now: float, record: r.DNSRecord) -> None:
            nonlocal updates
            updates.append(record)

    listener = LegacyRecordUpdateListener()

    zc.add_listener(listener, None)

    # dummy service callback
    def on_service_state_change(zeroconf, service_type, state_change, name):
        pass

    # start a browser
    type_ = "_homeassistant._tcp.local."
    name = "MyTestHome"
    browser = ServiceBrowser(zc, type_, [on_service_state_change])

    info_service = ServiceInfo(
        type_,
        '%s.%s' % (name, type_),
        80,
        0,
        0,
        {'path': '/~paulsm/'},
        "ash-2.local.",
        addresses=[socket.inet_aton("10.0.1.2")],
    )

    zc.register_service(info_service)

    zc.wait(1)

    browser.cancel()

    assert len(updates)
    assert len([isinstance(update, r.DNSPointer) and update.name == type_ for update in updates]) >= 1

    zc.remove_listener(listener)
    # Removing a second time should not throw
    zc.remove_listener(listener)

    zc.close()


def test_service_browser_is_aware_of_port_changes():
    """Test that the ServiceBrowser is aware of port changes."""

    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])
    # start a browser
    type_ = "_hap._tcp.local."
    registration_name = "xxxyyy.%s" % type_

    callbacks = []
    # dummy service callback
    def on_service_state_change(zeroconf, service_type, state_change, name):
        nonlocal callbacks
        if name == registration_name:
            callbacks.append((service_type, state_change, name))

    browser = ServiceBrowser(zc, type_, [on_service_state_change])

    desc = {'path': '/~paulsm/'}
    address_parsed = "10.0.1.2"
    address = socket.inet_aton(address_parsed)
    info = ServiceInfo(type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[address])

    def mock_incoming_msg(records) -> r.DNSIncoming:
        generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
        for record in records:
            generated.add_answer_at_time(record, 0)
        return r.DNSIncoming(generated.packets()[0])

    _inject_response(
        zc,
        mock_incoming_msg([info.dns_pointer(), info.dns_service(), info.dns_text(), *info.dns_addresses()]),
    )
    time.sleep(0.1)

    assert callbacks == [('_hap._tcp.local.', ServiceStateChange.Added, 'xxxyyy._hap._tcp.local.')]
    assert zc.get_service_info(type_, registration_name).port == 80

    info.port = 400
    _inject_response(
        zc,
        mock_incoming_msg([info.dns_service()]),
    )
    time.sleep(0.1)

    assert callbacks == [
        ('_hap._tcp.local.', ServiceStateChange.Added, 'xxxyyy._hap._tcp.local.'),
        ('_hap._tcp.local.', ServiceStateChange.Updated, 'xxxyyy._hap._tcp.local.'),
    ]
    assert zc.get_service_info(type_, registration_name).port == 400
    browser.cancel()

    zc.close()


def test_service_browser_listeners_update_service():
    """Test that the ServiceBrowser ServiceListener that implements update_service."""

    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])
    # start a browser
    type_ = "_hap._tcp.local."
    registration_name = "xxxyyy.%s" % type_
    callbacks = []

    class MyServiceListener(r.ServiceListener):
        def add_service(self, zc, type_, name) -> None:
            nonlocal callbacks
            if name == registration_name:
                callbacks.append(("add", type_, name))

        def remove_service(self, zc, type_, name) -> None:
            nonlocal callbacks
            if name == registration_name:
                callbacks.append(("remove", type_, name))

        def update_service(self, zc, type_, name) -> None:
            nonlocal callbacks
            if name == registration_name:
                callbacks.append(("update", type_, name))

    listener = MyServiceListener()

    browser = r.ServiceBrowser(zc, type_, None, listener)

    desc = {'path': '/~paulsm/'}
    address_parsed = "10.0.1.2"
    address = socket.inet_aton(address_parsed)
    info = ServiceInfo(type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[address])

    def mock_incoming_msg(records) -> r.DNSIncoming:
        generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
        for record in records:
            generated.add_answer_at_time(record, 0)
        return r.DNSIncoming(generated.packets()[0])

    _inject_response(
        zc,
        mock_incoming_msg([info.dns_pointer(), info.dns_service(), info.dns_text(), *info.dns_addresses()]),
    )
    time.sleep(0.2)
    info.port = 400
    _inject_response(
        zc,
        mock_incoming_msg([info.dns_service()]),
    )
    time.sleep(0.2)

    assert callbacks == [
        ('add', type_, registration_name),
        ('update', type_, registration_name),
    ]
    browser.cancel()

    zc.close()


def test_service_browser_listeners_no_update_service():
    """Test that the ServiceBrowser ServiceListener that does not implement update_service."""

    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])
    # start a browser
    type_ = "_hap._tcp.local."
    registration_name = "xxxyyy.%s" % type_
    callbacks = []

    class MyServiceListener:
        def add_service(self, zc, type_, name) -> None:
            nonlocal callbacks
            if name == registration_name:
                callbacks.append(("add", type_, name))

        def remove_service(self, zc, type_, name) -> None:
            nonlocal callbacks
            if name == registration_name:
                callbacks.append(("remove", type_, name))

    listener = MyServiceListener()

    browser = r.ServiceBrowser(zc, type_, None, listener)

    desc = {'path': '/~paulsm/'}
    address_parsed = "10.0.1.2"
    address = socket.inet_aton(address_parsed)
    info = ServiceInfo(type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[address])

    def mock_incoming_msg(records) -> r.DNSIncoming:
        generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
        for record in records:
            generated.add_answer_at_time(record, 0)
        return r.DNSIncoming(generated.packets()[0])

    _inject_response(
        zc,
        mock_incoming_msg([info.dns_pointer(), info.dns_service(), info.dns_text(), *info.dns_addresses()]),
    )
    time.sleep(0.2)
    info.port = 400
    _inject_response(
        zc,
        mock_incoming_msg([info.dns_service()]),
    )
    time.sleep(0.2)

    assert callbacks == [
        ('add', type_, registration_name),
    ]
    browser.cancel()

    zc.close()


def test_servicebrowser_uses_non_strict_names():
    """Verify we can look for technically invalid names as we cannot change what others do."""

    # dummy service callback
    def on_service_state_change(zeroconf, service_type, state_change, name):
        pass

    zc = r.Zeroconf(interfaces=['127.0.0.1'])
    browser = ServiceBrowser(zc, ["_tivo-videostream._tcp.local."], [on_service_state_change])
    browser.cancel()

    # Still fail on completely invalid
    with pytest.raises(r.BadTypeInNameException):
        browser = ServiceBrowser(zc, ["tivo-videostream._tcp.local."], [on_service_state_change])
    zc.close()


def test_group_ptr_queries_with_known_answers():
    questions_with_known_answers: _services_browser._QuestionWithKnownAnswers = {}
    now = current_time_millis()
    for i in range(120):
        name = f"_hap{i}._tcp._local."
        questions_with_known_answers[DNSQuestion(name, const._TYPE_PTR, const._CLASS_IN)] = set(
            DNSPointer(
                name,
                const._TYPE_PTR,
                const._CLASS_IN,
                4500,
                f"zoo{counter}.{name}",
            )
            for counter in range(i)
        )
    outs = _services_browser._group_ptr_queries_with_known_answers(now, True, questions_with_known_answers)
    for out in outs:
        packets = out.packets()
        # If we generate multiple packets there must
        # only be one question
        assert len(packets) == 1 or len(out.questions) == 1
