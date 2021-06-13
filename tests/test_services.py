#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf.services. """

import logging
import socket
import threading
import time
from threading import Event

import pytest

import zeroconf as r
import zeroconf.services as s
from zeroconf import (
    ServiceBrowser,
    ServiceInfo,
    ServiceStateChange,
    Zeroconf,
)

log = logging.getLogger('zeroconf')
original_logging_level = logging.NOTSET


@pytest.fixture(autouse=True)
def verify_threads_ended():
    """Verify that the threads are not running after the test."""
    threads_before = frozenset(threading.enumerate())
    yield
    threads = frozenset(threading.enumerate()) - threads_before
    assert not threads


def setup_module():
    global original_logging_level
    original_logging_level = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    if original_logging_level != logging.NOTSET:
        log.setLevel(original_logging_level)


def test_backoff():
    got_query = Event()

    type_ = "_http._tcp.local."
    zeroconf_browser = Zeroconf(interfaces=['127.0.0.1'])

    # we are going to monkey patch the zeroconf send to check query transmission
    old_send = zeroconf_browser.send

    time_offset = 0.0
    start_time = time.time() * 1000
    initial_query_interval = s._BROWSER_TIME / 1000

    def current_time_millis():
        """Current system time in milliseconds"""
        return start_time + time_offset * 1000

    def send(out, addr=r._MDNS_ADDR, port=r._MDNS_PORT):
        """Sends an outgoing packet."""
        got_query.set()
        old_send(out, addr=addr, port=port)

    # monkey patch the zeroconf send
    setattr(zeroconf_browser, "send", send)

    # monkey patch the zeroconf current_time_millis
    s.current_time_millis = current_time_millis

    # monkey patch the backoff limit to prevent test running forever
    s._BROWSER_BACKOFF_LIMIT = 10  # seconds

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
            zeroconf_browser.notify_all()
            sleep_count += 1
            got_query.wait(0.1)
            if time_offset == expected_query_time:
                assert got_query.is_set()
                got_query.clear()
                if next_query_interval == s._BROWSER_BACKOFF_LIMIT:
                    # Only need to test up to the point where we've seen a query
                    # after the backoff limit has been hit
                    break
                elif next_query_interval == 0:
                    next_query_interval = initial_query_interval
                    expected_query_time = initial_query_interval
                else:
                    next_query_interval = min(2 * next_query_interval, s._BROWSER_BACKOFF_LIMIT)
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

    # we are going to monkey patch the zeroconf send to check packet sizes
    old_send = zeroconf_browser.send

    time_offset = 0.0

    def current_time_millis():
        """Current system time in milliseconds"""
        return time.time() * 1000 + time_offset * 1000

    expected_ttl = r._DNS_HOST_TTL

    nbr_answers = 0

    def send(out, addr=r._MDNS_ADDR, port=r._MDNS_PORT):
        """Sends an outgoing packet."""
        pout = r.DNSIncoming(out.packet())
        nonlocal nbr_answers
        for answer in pout.answers:
            nbr_answers += 1
            if not answer.ttl > expected_ttl / 2:
                unexpected_ttl.set()

        got_query.set()
        old_send(out, addr=addr, port=port)

    # monkey patch the zeroconf send
    setattr(zeroconf_browser, "send", send)

    # monkey patch the zeroconf current_time_millis
    s.current_time_millis = current_time_millis

    # monkey patch the backoff limit to ensure we always get one query every 1/4 of the DNS TTL
    s._BROWSER_BACKOFF_LIMIT = int(expected_ttl / 4)

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
            got_query.clear()
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
            zc, 0, r.DNSRecord('irrelevant', r._TYPE_SRV, r._CLASS_IN, r._DNS_HOST_TTL)
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
