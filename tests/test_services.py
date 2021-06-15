#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf._services. """

import logging
import socket
import threading
import time
import os
import unittest
from threading import Event
from typing import List

import pytest

import zeroconf as r
from zeroconf import DNSAddress, const
import zeroconf._services as s
from zeroconf import Zeroconf
from zeroconf._services import (
    ServiceBrowser,
    ServiceInfo,
    ServiceStateChange,
)

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


class TestServiceInfo(unittest.TestCase):
    def test_get_name(self):
        """Verify the name accessor can strip the type."""
        desc = {'path': '/~paulsm/'}
        service_name = 'name._type._tcp.local.'
        service_type = '_type._tcp.local.'
        service_server = 'ash-1.local.'
        service_address = socket.inet_aton("10.0.1.2")
        info = ServiceInfo(
            service_type, service_name, 22, 0, 0, desc, service_server, addresses=[service_address]
        )
        assert info.get_name() == "name"

    def test_service_info_rejects_non_matching_updates(self):
        """Verify records with the wrong name are rejected."""

        zc = r.Zeroconf(interfaces=['127.0.0.1'])
        desc = {'path': '/~paulsm/'}
        service_name = 'name._type._tcp.local.'
        service_type = '_type._tcp.local.'
        service_server = 'ash-1.local.'
        service_address = socket.inet_aton("10.0.1.2")
        ttl = 120
        now = r.current_time_millis()
        info = ServiceInfo(
            service_type, service_name, 22, 0, 0, desc, service_server, addresses=[service_address]
        )
        # Verify backwards compatiblity with calling with None
        info.update_record(zc, now, None)
        # Matching updates
        info.update_record(
            zc,
            now,
            r.DNSText(
                service_name,
                const._TYPE_TXT,
                const._CLASS_IN | const._CLASS_UNIQUE,
                ttl,
                b'\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==',
            ),
        )
        assert info.properties[b"ci"] == b"2"
        info.update_record(
            zc,
            now,
            r.DNSService(
                service_name,
                const._TYPE_SRV,
                const._CLASS_IN | const._CLASS_UNIQUE,
                ttl,
                0,
                0,
                80,
                'ASH-2.local.',
            ),
        )
        assert info.server_key == 'ash-2.local.'
        assert info.server == 'ASH-2.local.'
        new_address = socket.inet_aton("10.0.1.3")
        info.update_record(
            zc,
            now,
            r.DNSAddress(
                'ASH-2.local.',
                const._TYPE_A,
                const._CLASS_IN | const._CLASS_UNIQUE,
                ttl,
                new_address,
            ),
        )
        assert new_address in info.addresses
        # Non-matching updates
        info.update_record(
            zc,
            now,
            r.DNSText(
                "incorrect.name.",
                const._TYPE_TXT,
                const._CLASS_IN | const._CLASS_UNIQUE,
                ttl,
                b'\x04ff=0\x04ci=3\x04sf=0\x0bsh=6fLM5A==',
            ),
        )
        assert info.properties[b"ci"] == b"2"
        info.update_record(
            zc,
            now,
            r.DNSService(
                "incorrect.name.",
                const._TYPE_SRV,
                const._CLASS_IN | const._CLASS_UNIQUE,
                ttl,
                0,
                0,
                80,
                'ASH-2.local.',
            ),
        )
        assert info.server_key == 'ash-2.local.'
        assert info.server == 'ASH-2.local.'
        new_address = socket.inet_aton("10.0.1.4")
        info.update_record(
            zc,
            now,
            r.DNSAddress(
                "incorrect.name.",
                const._TYPE_A,
                const._CLASS_IN | const._CLASS_UNIQUE,
                ttl,
                new_address,
            ),
        )
        assert new_address not in info.addresses
        zc.close()

    def test_service_info_rejects_expired_records(self):
        """Verify records that are expired are rejected."""
        zc = r.Zeroconf(interfaces=['127.0.0.1'])
        desc = {'path': '/~paulsm/'}
        service_name = 'name._type._tcp.local.'
        service_type = '_type._tcp.local.'
        service_server = 'ash-1.local.'
        service_address = socket.inet_aton("10.0.1.2")
        ttl = 120
        now = r.current_time_millis()
        info = ServiceInfo(
            service_type, service_name, 22, 0, 0, desc, service_server, addresses=[service_address]
        )
        # Matching updates
        info.update_record(
            zc,
            now,
            r.DNSText(
                service_name,
                const._TYPE_TXT,
                const._CLASS_IN | const._CLASS_UNIQUE,
                ttl,
                b'\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==',
            ),
        )
        assert info.properties[b"ci"] == b"2"
        # Expired record
        expired_record = r.DNSText(
            service_name,
            const._TYPE_TXT,
            const._CLASS_IN | const._CLASS_UNIQUE,
            ttl,
            b'\x04ff=0\x04ci=3\x04sf=0\x0bsh=6fLM5A==',
        )
        expired_record.created = 1000
        expired_record._expiration_time = 1000
        info.update_record(zc, now, expired_record)
        assert info.properties[b"ci"] == b"2"
        zc.close()

    def test_get_info_partial(self):

        zc = r.Zeroconf(interfaces=['127.0.0.1'])

        service_name = 'name._type._tcp.local.'
        service_type = '_type._tcp.local.'
        service_server = 'ash-1.local.'
        service_text = b'path=/~matt1/'
        service_address = '10.0.1.2'

        service_info = None
        send_event = Event()
        service_info_event = Event()

        last_sent = None  # type: Optional[r.DNSOutgoing]

        def send(out, addr=const._MDNS_ADDR, port=const._MDNS_PORT):
            """Sends an outgoing packet."""
            nonlocal last_sent

            last_sent = out
            send_event.set()

        # patch the zeroconf send
        with unittest.mock.patch.object(zc, "send", send):

            def mock_incoming_msg(records) -> r.DNSIncoming:

                generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)

                for record in records:
                    generated.add_answer_at_time(record, 0)

                return r.DNSIncoming(generated.packets()[0])

            def get_service_info_helper(zc, type, name):
                nonlocal service_info
                service_info = zc.get_service_info(type, name)
                service_info_event.set()

            try:
                ttl = 120
                helper_thread = threading.Thread(
                    target=get_service_info_helper, args=(zc, service_type, service_name)
                )
                helper_thread.start()
                wait_time = 1

                # Expext query for SRV, TXT, A, AAAA
                send_event.wait(wait_time)
                assert last_sent is not None
                assert len(last_sent.questions) == 4
                assert r.DNSQuestion(service_name, const._TYPE_SRV, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_TXT, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_A, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_AAAA, const._CLASS_IN) in last_sent.questions
                assert service_info is None

                # Expext query for SRV, A, AAAA
                last_sent = None
                send_event.clear()
                _inject_response(
                    zc,
                    mock_incoming_msg(
                        [
                            r.DNSText(
                                service_name,
                                const._TYPE_TXT,
                                const._CLASS_IN | const._CLASS_UNIQUE,
                                ttl,
                                service_text,
                            )
                        ]
                    ),
                )
                send_event.wait(wait_time)
                assert last_sent is not None
                assert len(last_sent.questions) == 3
                assert r.DNSQuestion(service_name, const._TYPE_SRV, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_A, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_AAAA, const._CLASS_IN) in last_sent.questions
                assert service_info is None

                # Expext query for A, AAAA
                last_sent = None
                send_event.clear()
                _inject_response(
                    zc,
                    mock_incoming_msg(
                        [
                            r.DNSService(
                                service_name,
                                const._TYPE_SRV,
                                const._CLASS_IN | const._CLASS_UNIQUE,
                                ttl,
                                0,
                                0,
                                80,
                                service_server,
                            )
                        ]
                    ),
                )
                send_event.wait(wait_time)
                assert last_sent is not None
                assert len(last_sent.questions) == 2
                assert r.DNSQuestion(service_server, const._TYPE_A, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_server, const._TYPE_AAAA, const._CLASS_IN) in last_sent.questions
                last_sent = None
                assert service_info is None

                # Expext no further queries
                last_sent = None
                send_event.clear()
                _inject_response(
                    zc,
                    mock_incoming_msg(
                        [
                            r.DNSAddress(
                                service_server,
                                const._TYPE_A,
                                const._CLASS_IN | const._CLASS_UNIQUE,
                                ttl,
                                socket.inet_pton(socket.AF_INET, service_address),
                            )
                        ]
                    ),
                )
                send_event.wait(wait_time)
                assert last_sent is None
                assert service_info is not None

            finally:
                helper_thread.join()
                zc.remove_all_service_listeners()
                zc.close()

    def test_get_info_single(self):

        zc = r.Zeroconf(interfaces=['127.0.0.1'])

        service_name = 'name._type._tcp.local.'
        service_type = '_type._tcp.local.'
        service_server = 'ash-1.local.'
        service_text = b'path=/~matt1/'
        service_address = '10.0.1.2'

        service_info = None
        send_event = Event()
        service_info_event = Event()

        last_sent = None  # type: Optional[r.DNSOutgoing]

        def send(out, addr=const._MDNS_ADDR, port=const._MDNS_PORT):
            """Sends an outgoing packet."""
            nonlocal last_sent

            last_sent = out
            send_event.set()

        # patch the zeroconf send
        with unittest.mock.patch.object(zc, "send", send):

            def mock_incoming_msg(records) -> r.DNSIncoming:

                generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)

                for record in records:
                    generated.add_answer_at_time(record, 0)

                return r.DNSIncoming(generated.packets()[0])

            def get_service_info_helper(zc, type, name):
                nonlocal service_info
                service_info = zc.get_service_info(type, name)
                service_info_event.set()

            try:
                ttl = 120
                helper_thread = threading.Thread(
                    target=get_service_info_helper, args=(zc, service_type, service_name)
                )
                helper_thread.start()
                wait_time = 1

                # Expext query for SRV, TXT, A, AAAA
                send_event.wait(wait_time)
                assert last_sent is not None
                assert len(last_sent.questions) == 4
                assert r.DNSQuestion(service_name, const._TYPE_SRV, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_TXT, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_A, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_AAAA, const._CLASS_IN) in last_sent.questions
                assert service_info is None

                # Expext no further queries
                last_sent = None
                send_event.clear()
                _inject_response(
                    zc,
                    mock_incoming_msg(
                        [
                            r.DNSText(
                                service_name,
                                const._TYPE_TXT,
                                const._CLASS_IN | const._CLASS_UNIQUE,
                                ttl,
                                service_text,
                            ),
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
                            r.DNSAddress(
                                service_server,
                                const._TYPE_A,
                                const._CLASS_IN | const._CLASS_UNIQUE,
                                ttl,
                                socket.inet_pton(socket.AF_INET, service_address),
                            ),
                        ]
                    ),
                )
                send_event.wait(wait_time)
                assert last_sent is None
                assert service_info is not None

            finally:
                helper_thread.join()
                zc.remove_all_service_listeners()
                zc.close()


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


class ListenerTest(unittest.TestCase):
    def test_integration_with_listener_class(self):

        service_added = Event()
        service_removed = Event()
        service_updated = Event()
        service_updated2 = Event()

        subtype_name = "My special Subtype"
        type_ = "_http._tcp.local."
        subtype = subtype_name + "._sub." + type_
        name = "UPPERxxxyyyæøå"
        registration_name = "%s.%s" % (name, subtype)

        class MyListener(r.ServiceListener):
            def add_service(self, zeroconf, type, name):
                zeroconf.get_service_info(type, name)
                service_added.set()

            def remove_service(self, zeroconf, type, name):
                service_removed.set()

            def update_service(self, zeroconf, type, name):
                service_updated2.set()

        class MySubListener(r.ServiceListener):
            def add_service(self, zeroconf, type, name):
                pass

            def remove_service(self, zeroconf, type, name):
                pass

            def update_service(self, zeroconf, type, name):
                service_updated.set()

        listener = MyListener()
        zeroconf_browser = Zeroconf(interfaces=['127.0.0.1'])
        zeroconf_browser.add_service_listener(subtype, listener)

        properties = dict(
            prop_none=None,
            prop_string=b'a_prop',
            prop_float=1.0,
            prop_blank=b'a blanked string',
            prop_true=1,
            prop_false=0,
        )

        zeroconf_registrar = Zeroconf(interfaces=['127.0.0.1'])
        desc = {'path': '/~paulsm/'}  # type: Dict
        desc.update(properties)
        addresses = [socket.inet_aton("10.0.1.2")]
        if has_working_ipv6() and not os.environ.get('SKIP_IPV6'):
            addresses.append(socket.inet_pton(socket.AF_INET6, "6001:db8::1"))
            addresses.append(socket.inet_pton(socket.AF_INET6, "2001:db8::1"))
        info_service = ServiceInfo(
            subtype, registration_name, port=80, properties=desc, server="ash-2.local.", addresses=addresses
        )
        zeroconf_registrar.register_service(info_service)

        try:
            service_added.wait(1)
            assert service_added.is_set()

            # short pause to allow multicast timers to expire
            time.sleep(3)

            # clear the answer cache to force query
            _clear_cache(zeroconf_browser)

            cached_info = ServiceInfo(type_, registration_name)
            cached_info.load_from_cache(zeroconf_browser)
            assert cached_info.properties == {}

            # get service info without answer cache
            info = zeroconf_browser.get_service_info(type_, registration_name)
            assert info is not None
            assert info.properties[b'prop_none'] is None
            assert info.properties[b'prop_string'] == properties['prop_string']
            assert info.properties[b'prop_float'] == b'1.0'
            assert info.properties[b'prop_blank'] == properties['prop_blank']
            assert info.properties[b'prop_true'] == b'1'
            assert info.properties[b'prop_false'] == b'0'
            assert info.addresses == addresses[:1]  # no V6 by default
            assert set(info.addresses_by_version(r.IPVersion.All)) == set(addresses)

            cached_info = ServiceInfo(type_, registration_name)
            cached_info.load_from_cache(zeroconf_browser)
            assert cached_info.properties is not None

            # Populate the cache
            zeroconf_browser.get_service_info(subtype, registration_name)

            # get service info with only the cache
            cached_info = ServiceInfo(subtype, registration_name)
            cached_info.load_from_cache(zeroconf_browser)
            assert cached_info.properties is not None
            assert cached_info.properties[b'prop_float'] == b'1.0'

            # get service info with only the cache with the lowercase name
            cached_info = ServiceInfo(subtype, registration_name.lower())
            cached_info.load_from_cache(zeroconf_browser)
            # Ensure uppercase output is preserved
            assert cached_info.name == registration_name
            assert cached_info.key == registration_name.lower()
            assert cached_info.properties is not None
            assert cached_info.properties[b'prop_float'] == b'1.0'

            info = zeroconf_browser.get_service_info(subtype, registration_name)
            assert info is not None
            assert info.properties is not None
            assert info.properties[b'prop_none'] is None

            cached_info = ServiceInfo(subtype, registration_name.lower())
            cached_info.load_from_cache(zeroconf_browser)
            assert cached_info.properties is not None
            assert cached_info.properties[b'prop_none'] is None

            # test TXT record update
            sublistener = MySubListener()
            zeroconf_browser.add_service_listener(registration_name, sublistener)
            properties['prop_blank'] = b'an updated string'
            desc.update(properties)
            info_service = ServiceInfo(
                subtype,
                registration_name,
                80,
                0,
                0,
                desc,
                "ash-2.local.",
                addresses=[socket.inet_aton("10.0.1.2")],
            )
            zeroconf_registrar.update_service(info_service)
            service_updated.wait(1)
            assert service_updated.is_set()

            info = zeroconf_browser.get_service_info(type_, registration_name)
            assert info is not None
            assert info.properties[b'prop_blank'] == properties['prop_blank']

            cached_info = ServiceInfo(subtype, registration_name)
            cached_info.load_from_cache(zeroconf_browser)
            assert cached_info.properties is not None
            assert cached_info.properties[b'prop_blank'] == properties['prop_blank']

            zeroconf_registrar.unregister_service(info_service)
            service_removed.wait(1)
            assert service_removed.is_set()

        finally:
            zeroconf_registrar.close()
            zeroconf_browser.remove_service_listener(listener)
            zeroconf_browser.close()


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


def test_multiple_addresses():
    type_ = "_http._tcp.local."
    registration_name = "xxxyyy.%s" % type_
    desc = {'path': '/~paulsm/'}
    address_parsed = "10.0.1.2"
    address = socket.inet_aton(address_parsed)

    # New kwarg way
    info = ServiceInfo(type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[address, address])

    assert info.addresses == [address, address]

    info = ServiceInfo(
        type_,
        registration_name,
        80,
        0,
        0,
        desc,
        "ash-2.local.",
        parsed_addresses=[address_parsed, address_parsed],
    )
    assert info.addresses == [address, address]

    if has_working_ipv6() and not os.environ.get('SKIP_IPV6'):
        address_v6_parsed = "2001:db8::1"
        address_v6 = socket.inet_pton(socket.AF_INET6, address_v6_parsed)
        infos = [
            ServiceInfo(
                type_,
                registration_name,
                80,
                0,
                0,
                desc,
                "ash-2.local.",
                addresses=[address, address_v6],
            ),
            ServiceInfo(
                type_,
                registration_name,
                80,
                0,
                0,
                desc,
                "ash-2.local.",
                parsed_addresses=[address_parsed, address_v6_parsed],
            ),
        ]
        for info in infos:
            assert info.addresses == [address]
            assert info.addresses_by_version(r.IPVersion.All) == [address, address_v6]
            assert info.addresses_by_version(r.IPVersion.V4Only) == [address]
            assert info.addresses_by_version(r.IPVersion.V6Only) == [address_v6]
            assert info.parsed_addresses() == [address_parsed, address_v6_parsed]
            assert info.parsed_addresses(r.IPVersion.V4Only) == [address_parsed]
            assert info.parsed_addresses(r.IPVersion.V6Only) == [address_v6_parsed]


def test_backoff():
    got_query = Event()

    type_ = "_http._tcp.local."
    zeroconf_browser = Zeroconf(interfaces=['127.0.0.1'])

    # we are going to patch the zeroconf send to check query transmission
    old_send = zeroconf_browser.send

    time_offset = 0.0
    start_time = time.time() * 1000
    initial_query_interval = s._BROWSER_TIME / 1000

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
    with unittest.mock.patch.object(zeroconf_browser, "send", send), unittest.mock.patch.object(
        s, "current_time_millis", current_time_millis
    ), unittest.mock.patch.object(s, "_BROWSER_BACKOFF_LIMIT", 10):
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

    # we are going to patch the zeroconf send to check packet sizes
    old_send = zeroconf_browser.send

    time_offset = 0.0

    def current_time_millis():
        """Current system time in milliseconds"""
        return time.time() * 1000 + time_offset * 1000

    expected_ttl = const._DNS_HOST_TTL

    nbr_answers = 0

    def send(out, addr=const._MDNS_ADDR, port=const._MDNS_PORT):
        """Sends an outgoing packet."""
        pout = r.DNSIncoming(out.packets()[0])
        nonlocal nbr_answers
        for answer in pout.answers:
            nbr_answers += 1
            if not answer.ttl > expected_ttl / 2:
                unexpected_ttl.set()

        got_query.set()
        old_send(out, addr=addr, port=port)

    # patch the zeroconf send
    # patch the zeroconf current_time_millis
    # patch the backoff limit to ensure we always get one query every 1/4 of the DNS TTL
    with unittest.mock.patch.object(zeroconf_browser, "send", send), unittest.mock.patch.object(
        s, "current_time_millis", current_time_millis
    ), unittest.mock.patch.object(s, "_BROWSER_BACKOFF_LIMIT", int(expected_ttl / 4)):
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


def test_filter_address_by_type_from_service_info():
    """Verify dns_addresses can filter by ipversion."""
    desc = {'path': '/~paulsm/'}
    type_ = "_homeassistant._tcp.local."
    name = "MyTestHome"
    registration_name = "%s.%s" % (name, type_)
    ipv4 = socket.inet_aton("10.0.1.2")
    ipv6 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    info = ServiceInfo(type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[ipv4, ipv6])

    def dns_addresses_to_addresses(dns_address: List[DNSAddress]):
        return [address.address for address in dns_address]

    assert dns_addresses_to_addresses(info.dns_addresses()) == [ipv4, ipv6]
    assert dns_addresses_to_addresses(info.dns_addresses(version=r.IPVersion.All)) == [ipv4, ipv6]
    assert dns_addresses_to_addresses(info.dns_addresses(version=r.IPVersion.V4Only)) == [ipv4]
    assert dns_addresses_to_addresses(info.dns_addresses(version=r.IPVersion.V6Only)) == [ipv6]


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
    zc.wait(100)

    assert callbacks == [('_hap._tcp.local.', ServiceStateChange.Added, 'xxxyyy._hap._tcp.local.')]
    assert zc.get_service_info(type_, registration_name).port == 80

    info.port = 400
    _inject_response(
        zc,
        mock_incoming_msg([info.dns_service()]),
    )
    zc.wait(100)

    assert callbacks == [
        ('_hap._tcp.local.', ServiceStateChange.Added, 'xxxyyy._hap._tcp.local.'),
        ('_hap._tcp.local.', ServiceStateChange.Updated, 'xxxyyy._hap._tcp.local.'),
    ]
    assert zc.get_service_info(type_, registration_name).port == 400
    browser.cancel()

    zc.close()


def test_changing_name_updates_serviceinfo_key():
    """Verify a name change will adjust the underlying key value."""
    type_ = "_homeassistant._tcp.local."
    name = "MyTestHome"
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
    assert info_service.key == "mytesthome._homeassistant._tcp.local."
    info_service.name = "YourTestHome._homeassistant._tcp.local."
    assert info_service.key == "yourtesthome._homeassistant._tcp.local."


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
