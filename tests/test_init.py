#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf.py """

import errno
import logging
import os
import socket
import time
import unittest
import unittest.mock
from threading import Event
from typing import Dict, Optional  # noqa # used in type hints

import pytest

import zeroconf as r
from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf, ZeroconfServiceTypes, const

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


class Names(unittest.TestCase):
    def test_long_name(self):
        generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion(
            "this.is.a.very.long.name.with.lots.of.parts.in.it.local.", const._TYPE_SRV, const._CLASS_IN
        )
        generated.add_question(question)
        r.DNSIncoming(generated.packets()[0])

    def test_exceedingly_long_name(self):
        generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
        name = "%slocal." % ("part." * 1000)
        question = r.DNSQuestion(name, const._TYPE_SRV, const._CLASS_IN)
        generated.add_question(question)
        r.DNSIncoming(generated.packets()[0])

    def test_extra_exceedingly_long_name(self):
        generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
        name = "%slocal." % ("part." * 4000)
        question = r.DNSQuestion(name, const._TYPE_SRV, const._CLASS_IN)
        generated.add_question(question)
        r.DNSIncoming(generated.packets()[0])

    def test_exceedingly_long_name_part(self):
        name = "%s.local." % ("a" * 1000)
        generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion(name, const._TYPE_SRV, const._CLASS_IN)
        generated.add_question(question)
        self.assertRaises(r.NamePartTooLongException, generated.packets)

    def test_same_name(self):
        name = "paired.local."
        generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion(name, const._TYPE_SRV, const._CLASS_IN)
        generated.add_question(question)
        generated.add_question(question)
        r.DNSIncoming(generated.packets()[0])

    def test_lots_of_names(self):

        # instantiate a zeroconf instance
        zc = Zeroconf(interfaces=['127.0.0.1'])

        # create a bunch of servers
        type_ = "_my-service._tcp.local."
        name = 'a wonderful service'
        server_count = 300
        self.generate_many_hosts(zc, type_, name, server_count)

        # verify that name changing works
        self.verify_name_change(zc, type_, name, server_count)

        # we are going to monkey patch the zeroconf send to check packet sizes
        old_send = zc.send

        longest_packet_len = 0
        longest_packet = None  # type: Optional[r.DNSOutgoing]

        def send(out, addr=const._MDNS_ADDR, port=const._MDNS_PORT):
            """Sends an outgoing packet."""
            for packet in out.packets():
                nonlocal longest_packet_len, longest_packet
                if longest_packet_len < len(packet):
                    longest_packet_len = len(packet)
                    longest_packet = out
                old_send(out, addr=addr, port=port)

        # monkey patch the zeroconf send
        setattr(zc, "send", send)

        # dummy service callback
        def on_service_state_change(zeroconf, service_type, state_change, name):
            pass

        # start a browser
        browser = ServiceBrowser(zc, type_, [on_service_state_change])

        # wait until the browse request packet has maxed out in size
        sleep_count = 0
        # we will never get to this large of a packet given the application-layer
        # splitting of packets, but we still want to track the longest_packet_len
        # for the debug message below
        while sleep_count < 100 and longest_packet_len < const._MAX_MSG_ABSOLUTE - 100:
            sleep_count += 1
            time.sleep(0.1)

        browser.cancel()
        time.sleep(0.5)

        import zeroconf

        zeroconf.log.debug('sleep_count %d, sized %d', sleep_count, longest_packet_len)

        # now the browser has sent at least one request, verify the size
        assert longest_packet_len <= const._MAX_MSG_TYPICAL
        assert longest_packet_len >= const._MAX_MSG_TYPICAL - 100

        # mock zeroconf's logger warning() and debug()
        from unittest.mock import patch

        patch_warn = patch('zeroconf.log.warning')
        patch_debug = patch('zeroconf.log.debug')
        mocked_log_warn = patch_warn.start()
        mocked_log_debug = patch_debug.start()

        # now that we have a long packet in our possession, let's verify the
        # exception handling.
        out = longest_packet
        assert out is not None
        out.data.append(b'\0' * 1000)

        # mock the zeroconf logger and check for the correct logging backoff
        call_counts = mocked_log_warn.call_count, mocked_log_debug.call_count
        # try to send an oversized packet
        zc.send(out)
        assert mocked_log_warn.call_count == call_counts[0]
        zc.send(out)
        assert mocked_log_warn.call_count == call_counts[0]

        # force a receive of a packet
        packet = out.packets()[0]
        s = zc._respond_sockets[0]

        # mock the zeroconf logger and check for the correct logging backoff
        call_counts = mocked_log_warn.call_count, mocked_log_debug.call_count
        # force receive on oversized packet
        s.sendto(packet, 0, (const._MDNS_ADDR, const._MDNS_PORT))
        s.sendto(packet, 0, (const._MDNS_ADDR, const._MDNS_PORT))
        time.sleep(2.0)
        zeroconf.log.debug(
            'warn %d debug %d was %s', mocked_log_warn.call_count, mocked_log_debug.call_count, call_counts
        )
        assert mocked_log_debug.call_count > call_counts[0]

        # close our zeroconf which will close the sockets
        zc.close()

        # pop the big chunk off the end of the data and send on a closed socket
        out.data.pop()
        zc._GLOBAL_DONE = False

        # mock the zeroconf logger and check for the correct logging backoff
        call_counts = mocked_log_warn.call_count, mocked_log_debug.call_count
        # send on a closed socket (force a socket error)
        zc.send(out)
        zeroconf.log.debug(
            'warn %d debug %d was %s', mocked_log_warn.call_count, mocked_log_debug.call_count, call_counts
        )
        assert mocked_log_warn.call_count > call_counts[0]
        assert mocked_log_debug.call_count > call_counts[0]
        zc.send(out)
        zeroconf.log.debug(
            'warn %d debug %d was %s', mocked_log_warn.call_count, mocked_log_debug.call_count, call_counts
        )
        assert mocked_log_debug.call_count > call_counts[0] + 2

        mocked_log_warn.stop()
        mocked_log_debug.stop()

    def verify_name_change(self, zc, type_, name, number_hosts):
        desc = {'path': '/~paulsm/'}
        info_service = ServiceInfo(
            type_,
            '%s.%s' % (name, type_),
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )

        # verify name conflict
        self.assertRaises(r.NonUniqueNameException, zc.register_service, info_service)

        # verify no name conflict https://tools.ietf.org/html/rfc6762#section-6.6
        zc.register_service(info_service, cooperating_responders=True)

        zc.register_service(info_service, allow_name_change=True)
        assert info_service.name.split('.')[0] == '%s-%d' % (name, number_hosts + 1)

    def generate_many_hosts(self, zc, type_, name, number_hosts):
        records_per_server = 2
        block_size = 25
        number_hosts = int(((number_hosts - 1) / block_size + 1)) * block_size
        for i in range(1, number_hosts + 1):
            next_name = name if i == 1 else '%s-%d' % (name, i)
            self.generate_host(zc, next_name, type_)
            if i % block_size == 0:
                sleep_count = 0
                while sleep_count < 40 and i * records_per_server > len(zc.cache.entries_with_name(type_)):
                    sleep_count += 1
                    time.sleep(0.05)

    @staticmethod
    def generate_host(zc, host_name, type_):
        name = '.'.join((host_name, type_))
        out = r.DNSOutgoing(const._FLAGS_QR_RESPONSE | const._FLAGS_AA)
        out.add_answer_at_time(
            r.DNSPointer(type_, const._TYPE_PTR, const._CLASS_IN, const._DNS_OTHER_TTL, name), 0
        )
        out.add_answer_at_time(
            r.DNSService(
                type_,
                const._TYPE_SRV,
                const._CLASS_IN | const._CLASS_UNIQUE,
                const._DNS_HOST_TTL,
                0,
                0,
                80,
                name,
            ),
            0,
        )
        zc.send(out)


class TestRegistrar(unittest.TestCase):
    def test_ttl(self):

        # instantiate a zeroconf instance
        zc = Zeroconf(interfaces=['127.0.0.1'])

        # service definition
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )

        nbr_answers = nbr_additionals = nbr_authorities = 0

        def get_ttl(record_type):
            if expected_ttl is not None:
                return expected_ttl
            elif record_type in [const._TYPE_A, const._TYPE_SRV]:
                return const._DNS_HOST_TTL
            else:
                return const._DNS_OTHER_TTL

        def _process_outgoing_packet(out):
            """Sends an outgoing packet."""
            nonlocal nbr_answers, nbr_additionals, nbr_authorities

            for answer, time_ in out.answers:
                nbr_answers += 1
                assert answer.ttl == get_ttl(answer.type)
            for answer in out.additionals:
                nbr_additionals += 1
                assert answer.ttl == get_ttl(answer.type)
            for answer in out.authorities:
                nbr_authorities += 1
                assert answer.ttl == get_ttl(answer.type)

        # register service with default TTL
        expected_ttl = None
        for _ in range(3):
            _process_outgoing_packet(zc.generate_service_query(info))
        zc.registry.add(info)
        for _ in range(3):
            _process_outgoing_packet(zc.generate_service_broadcast(info, None))
        assert nbr_answers == 12 and nbr_additionals == 0 and nbr_authorities == 3
        nbr_answers = nbr_additionals = nbr_authorities = 0

        # query
        query = r.DNSOutgoing(const._FLAGS_QR_QUERY | const._FLAGS_AA)
        assert query.is_query() is True
        query.add_question(r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN))
        query.add_question(r.DNSQuestion(info.name, const._TYPE_SRV, const._CLASS_IN))
        query.add_question(r.DNSQuestion(info.name, const._TYPE_TXT, const._CLASS_IN))
        query.add_question(r.DNSQuestion(info.server, const._TYPE_A, const._CLASS_IN))
        _process_outgoing_packet(zc.query_handler.response(r.DNSIncoming(query.packets()[0]), False))
        assert nbr_answers == 4 and nbr_additionals == 4 and nbr_authorities == 0
        nbr_answers = nbr_additionals = nbr_authorities = 0

        # unregister
        expected_ttl = 0
        zc.registry.remove(info)
        for _ in range(3):
            _process_outgoing_packet(zc.generate_service_broadcast(info, 0))
        assert nbr_answers == 12 and nbr_additionals == 0 and nbr_authorities == 0
        nbr_answers = nbr_additionals = nbr_authorities = 0

        expected_ttl = None
        for _ in range(3):
            _process_outgoing_packet(zc.generate_service_query(info))
        zc.registry.add(info)
        # register service with custom TTL
        expected_ttl = const._DNS_HOST_TTL * 2
        assert expected_ttl != const._DNS_HOST_TTL
        for _ in range(3):
            _process_outgoing_packet(zc.generate_service_broadcast(info, expected_ttl))
        assert nbr_answers == 12 and nbr_additionals == 0 and nbr_authorities == 3
        nbr_answers = nbr_additionals = nbr_authorities = 0

        # query
        expected_ttl = None
        query = r.DNSOutgoing(const._FLAGS_QR_QUERY | const._FLAGS_AA)
        query.add_question(r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN))
        query.add_question(r.DNSQuestion(info.name, const._TYPE_SRV, const._CLASS_IN))
        query.add_question(r.DNSQuestion(info.name, const._TYPE_TXT, const._CLASS_IN))
        query.add_question(r.DNSQuestion(info.server, const._TYPE_A, const._CLASS_IN))
        _process_outgoing_packet(zc.query_handler.response(r.DNSIncoming(query.packets()[0]), False))
        assert nbr_answers == 4 and nbr_additionals == 4 and nbr_authorities == 0
        nbr_answers = nbr_additionals = nbr_authorities = 0

        # unregister
        expected_ttl = 0
        zc.registry.remove(info)
        for _ in range(3):
            _process_outgoing_packet(zc.generate_service_broadcast(info, 0))
        assert nbr_answers == 12 and nbr_additionals == 0 and nbr_authorities == 0
        nbr_answers = nbr_additionals = nbr_authorities = 0
        zc.close()

    def test_name_conflicts(self):
        # instantiate a zeroconf instance
        zc = Zeroconf(interfaces=['127.0.0.1'])
        type_ = "_homeassistant._tcp.local."
        name = "Home"
        registration_name = "%s.%s" % (name, type_)

        info = ServiceInfo(
            type_,
            name=registration_name,
            server="random123.local.",
            addresses=[socket.inet_pton(socket.AF_INET, "1.2.3.4")],
            port=80,
            properties={"version": "1.0"},
        )
        zc.register_service(info)

        conflicting_info = ServiceInfo(
            type_,
            name=registration_name,
            server="random456.local.",
            addresses=[socket.inet_pton(socket.AF_INET, "4.5.6.7")],
            port=80,
            properties={"version": "1.0"},
        )
        with pytest.raises(r.NonUniqueNameException):
            zc.register_service(conflicting_info)
        zc.close()

    def test_register_and_lookup_type_by_uppercase_name(self):
        # instantiate a zeroconf instance
        zc = Zeroconf(interfaces=['127.0.0.1'])
        type_ = "_mylowertype._tcp.local."
        name = "Home"
        registration_name = "%s.%s" % (name, type_)

        info = ServiceInfo(
            type_,
            name=registration_name,
            server="random123.local.",
            addresses=[socket.inet_pton(socket.AF_INET, "1.2.3.4")],
            port=80,
            properties={"version": "1.0"},
        )
        zc.register_service(info)
        _clear_cache(zc)
        info = ServiceInfo(type_, registration_name)
        info.load_from_cache(zc)
        assert info.addresses == []

        out = r.DNSOutgoing(const._FLAGS_QR_QUERY)
        out.add_question(r.DNSQuestion(type_.upper(), const._TYPE_PTR, const._CLASS_IN))
        zc.send(out)
        time.sleep(0.5)
        info = ServiceInfo(type_, registration_name)
        info.load_from_cache(zc)
        assert info.addresses == [socket.inet_pton(socket.AF_INET, "1.2.3.4")]
        assert info.properties == {b"version": b"1.0"}
        zc.close()


class TestServiceRegistry(unittest.TestCase):
    def test_only_register_once(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
        )

        registry = r.ServiceRegistry()
        registry.add(info)
        self.assertRaises(r.ServiceNameAlreadyRegistered, registry.add, info)
        registry.remove(info)
        registry.add(info)

    def test_lookups(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
        )

        registry = r.ServiceRegistry()
        registry.add(info)

        assert registry.get_service_infos() == [info]
        assert registry.get_info_name(registration_name) == info
        assert registry.get_infos_type(type_) == [info]
        assert registry.get_infos_server("ash-2.local.") == [info]
        assert registry.get_types() == [type_]


class ServiceTypesQuery(unittest.TestCase):
    def test_integration_with_listener(self):

        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        zeroconf_registrar = Zeroconf(interfaces=['127.0.0.1'])
        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )
        zeroconf_registrar.register_service(info)

        try:
            service_types = ZeroconfServiceTypes.find(interfaces=['127.0.0.1'], timeout=0.5)
            assert type_ in service_types
            _clear_cache(zeroconf_registrar)
            service_types = ZeroconfServiceTypes.find(zc=zeroconf_registrar, timeout=0.5)
            assert type_ in service_types

        finally:
            zeroconf_registrar.close()

    @unittest.skipIf(not has_working_ipv6(), 'Requires IPv6')
    @unittest.skipIf(os.environ.get('SKIP_IPV6'), 'IPv6 tests disabled')
    def test_integration_with_listener_v6_records(self):

        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)
        addr = "2606:2800:220:1:248:1893:25c8:1946"  # example.com

        zeroconf_registrar = Zeroconf(interfaces=['127.0.0.1'])
        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_pton(socket.AF_INET6, addr)],
        )
        zeroconf_registrar.register_service(info)

        try:
            service_types = ZeroconfServiceTypes.find(interfaces=['127.0.0.1'], timeout=0.5)
            assert type_ in service_types
            _clear_cache(zeroconf_registrar)
            service_types = ZeroconfServiceTypes.find(zc=zeroconf_registrar, timeout=0.5)
            assert type_ in service_types

        finally:
            zeroconf_registrar.close()

    @unittest.skipIf(not has_working_ipv6(), 'Requires IPv6')
    @unittest.skipIf(os.environ.get('SKIP_IPV6'), 'IPv6 tests disabled')
    def test_integration_with_listener_ipv6(self):

        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        zeroconf_registrar = Zeroconf(ip_version=r.IPVersion.V6Only)
        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )
        zeroconf_registrar.register_service(info)

        try:
            service_types = ZeroconfServiceTypes.find(ip_version=r.IPVersion.V6Only, timeout=0.5)
            assert type_ in service_types
            _clear_cache(zeroconf_registrar)
            service_types = ZeroconfServiceTypes.find(zc=zeroconf_registrar, timeout=0.5)
            assert type_ in service_types

        finally:
            zeroconf_registrar.close()

    def test_integration_with_subtype_and_listener(self):
        subtype_ = "_subtype._sub"
        type_ = "_type._tcp.local."
        name = "xxxyyy"
        # Note: discovery returns only DNS-SD type not subtype
        discovery_type = "%s.%s" % (subtype_, type_)
        registration_name = "%s.%s" % (name, type_)

        zeroconf_registrar = Zeroconf(interfaces=['127.0.0.1'])
        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            discovery_type,
            registration_name,
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )
        zeroconf_registrar.register_service(info)

        try:
            service_types = ZeroconfServiceTypes.find(interfaces=['127.0.0.1'], timeout=0.5)
            assert discovery_type in service_types
            _clear_cache(zeroconf_registrar)
            service_types = ZeroconfServiceTypes.find(zc=zeroconf_registrar, timeout=0.5)
            assert discovery_type in service_types

        finally:
            zeroconf_registrar.close()


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
            assert info.addresses_by_version(r.IPVersion.All) == addresses

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


def test_ptr_optimization():

    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])

    # service definition
    type_ = "_test-srvc-type._tcp.local."
    name = "xxxyyy"
    registration_name = "%s.%s" % (name, type_)

    desc = {'path': '/~paulsm/'}
    info = ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
    )

    nbr_answers = nbr_additionals = nbr_authorities = 0
    has_srv = has_txt = has_a = False

    # register
    zc.register_service(info)
    nbr_answers = nbr_additionals = nbr_authorities = 0

    # query
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY | const._FLAGS_AA)
    query.add_question(r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN))
    out = zc.query_handler.response(r.DNSIncoming(query.packets()[0]), False)
    assert out is not None
    nbr_answers += len(out.answers)
    nbr_authorities += len(out.authorities)
    for answer in out.additionals:
        nbr_additionals += 1
        if answer.type == const._TYPE_SRV:
            has_srv = True
        elif answer.type == const._TYPE_TXT:
            has_txt = True
        elif answer.type == const._TYPE_A:
            has_a = True
    assert nbr_answers == 1 and nbr_additionals == 3 and nbr_authorities == 0
    assert has_srv and has_txt and has_a

    # unregister
    zc.unregister_service(info)
    zc.close()


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


def test_autodetect_ip_version():
    """Tests for auto detecting IPVersion based on interface ips."""
    assert r.autodetect_ip_version(["1.3.4.5"]) is r.IPVersion.V4Only
    assert r.autodetect_ip_version([]) is r.IPVersion.V4Only
    assert r.autodetect_ip_version(["::1", "1.2.3.4"]) is r.IPVersion.All
    assert r.autodetect_ip_version(["::1"]) is r.IPVersion.V6Only
