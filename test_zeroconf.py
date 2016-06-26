#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf.py """

import logging
import socket
import struct
import time
import unittest
from threading import Event

from six import indexbytes
from six.moves import xrange

import zeroconf as r
from zeroconf import (
    DNSText,
    ServiceBrowser,
    ServiceInfo,
    ServiceStateChange,
    Zeroconf,
    ZeroconfServiceTypes,
)

log = logging.getLogger('zeroconf')
original_logging_level = [None]


def setup_module():
    original_logging_level[0] = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    log.setLevel(original_logging_level[0])


class PacketGeneration(unittest.TestCase):

    def test_parse_own_packet_simple(self):
        generated = r.DNSOutgoing(0)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_simple_unicast(self):
        generated = r.DNSOutgoing(0, 0)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_flags(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_question(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        generated.add_question(r.DNSQuestion("testname.local.", r._TYPE_SRV,
                                             r._CLASS_IN))
        r.DNSIncoming(generated.packet())

    def test_match_question(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        question = r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        parsed = r.DNSIncoming(generated.packet())
        self.assertEqual(len(generated.questions), 1)
        self.assertEqual(len(generated.questions), len(parsed.questions))
        self.assertEqual(question, parsed.questions[0])


class PacketForm(unittest.TestCase):

    def test_transaction_id(self):
        """ID must be zero in a DNS-SD packet"""
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        bytes = generated.packet()
        id = indexbytes(bytes, 0) << 8 | indexbytes(bytes, 1)
        self.assertEqual(id, 0)

    def test_query_header_bits(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        bytes = generated.packet()
        flags = indexbytes(bytes, 2) << 8 | indexbytes(bytes, 3)
        self.assertEqual(flags, 0x0)

    def test_response_header_bits(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        bytes = generated.packet()
        flags = indexbytes(bytes, 2) << 8 | indexbytes(bytes, 3)
        self.assertEqual(flags, 0x8000)

    def test_numbers(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        bytes = generated.packet()
        (numQuestions, numAnswers, numAuthorities,
         numAdditionals) = struct.unpack('!4H', bytes[4:12])
        self.assertEqual(numQuestions, 0)
        self.assertEqual(numAnswers, 0)
        self.assertEqual(numAuthorities, 0)
        self.assertEqual(numAdditionals, 0)

    def test_numbers_questions(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN)
        for i in xrange(10):
            generated.add_question(question)
        bytes = generated.packet()
        (numQuestions, numAnswers, numAuthorities,
         numAdditionals) = struct.unpack('!4H', bytes[4:12])
        self.assertEqual(numQuestions, 10)
        self.assertEqual(numAnswers, 0)
        self.assertEqual(numAuthorities, 0)
        self.assertEqual(numAdditionals, 0)


class Names(unittest.TestCase):

    def test_long_name(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion("this.is.a.very.long.name.with.lots.of.parts.in.it.local.",
                                 r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        r.DNSIncoming(generated.packet())

    def test_exceedingly_long_name(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        name = "%slocal." % ("part." * 1000)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        r.DNSIncoming(generated.packet())

    def test_exceedingly_long_name_part(self):
        name = "%s.local." % ("a" * 1000)
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        self.assertRaises(r.NamePartTooLongException, generated.packet)

    def test_same_name(self):
        name = "paired.local."
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion(name, r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        generated.add_question(question)
        r.DNSIncoming(generated.packet())


class Framework(unittest.TestCase):

    def test_launch_and_close(self):
        rv = r.Zeroconf()
        rv.close()


class Exceptions(unittest.TestCase):

    def test_bad_service_info_name(self):
        browser = Zeroconf()
        self.assertRaises(r.BadTypeInNameException,
                          browser.get_service_info, "type", "type_not")
        browser.close()


class ServiceTypesQuery(unittest.TestCase):

    def test_integration_with_listener(self):

        type_ = "_test_service_type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        zeroconf_registrar = Zeroconf(interfaces=['127.0.0.1'])
        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_, registration_name,
            socket.inet_aton("10.0.1.2"), 80, 0, 0,
            desc, "ash-2.local.")
        zeroconf_registrar.register_service(info)

        try:
            service_types = ZeroconfServiceTypes.find(timeout=0.5)
            assert type_ in service_types
            service_types = ZeroconfServiceTypes.find(
                zc=zeroconf_registrar, timeout=0.5)
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
            discovery_type, registration_name,
            socket.inet_aton("10.0.1.2"), 80, 0, 0,
            desc, "ash-2.local.")
        zeroconf_registrar.register_service(info)

        try:
            service_types = ZeroconfServiceTypes.find(timeout=0.5)
            print(service_types)
            assert discovery_type in service_types
            service_types = ZeroconfServiceTypes.find(
                zc=zeroconf_registrar, timeout=0.5)
            assert discovery_type in service_types

        finally:
            zeroconf_registrar.close()


class Listener(unittest.TestCase):

    def test_integration_with_listener_class(self):

        service_added = Event()
        service_removed = Event()

        type_ = "_http._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        class MyListener(object):
            def add_service(self, zeroconf, type, name):
                zeroconf.get_service_info(type, name)
                service_added.set()

            def remove_service(self, zeroconf, type, name):
                service_removed.set()

        zeroconf_browser = Zeroconf()
        zeroconf_browser.add_service_listener(type_, MyListener())

        properties = dict(
            prop_none=None,
            prop_string=b'a_prop',
            prop_float=1.0,
            prop_blank=b'a blanked string',
            prop_true=1,
            prop_false=0,
        )

        zeroconf_registrar = Zeroconf()
        desc = {'path': '/~paulsm/'}
        desc.update(properties)
        info = ServiceInfo(
            type_, registration_name,
            socket.inet_aton("10.0.1.2"), 80, 0, 0,
            desc, "ash-2.local.")
        zeroconf_registrar.register_service(info)

        try:
            service_added.wait(1)
            assert service_added.is_set()

            # short pause to allow multicast timers to expire
            time.sleep(2)

            # clear the answer cache to force query
            for record in zeroconf_browser.cache.entries():
                zeroconf_browser.cache.remove(record)

            # get service info without answer cache
            info = zeroconf_browser.get_service_info(type_, registration_name)

            assert info.properties[b'prop_none'] is False
            assert info.properties[b'prop_string'] == properties['prop_string']
            assert info.properties[b'prop_float'] is False
            assert info.properties[b'prop_blank'] == properties['prop_blank']
            assert info.properties[b'prop_true'] is True
            assert info.properties[b'prop_false'] is False

            zeroconf_registrar.unregister_service(info)
            service_removed.wait(1)
            assert service_removed.is_set()
        finally:
            zeroconf_registrar.close()
            zeroconf_browser.close()


def test_integration():
    service_added = Event()
    service_removed = Event()

    type_ = "_http._tcp.local."
    registration_name = "xxxyyy.%s" % type_

    def on_service_state_change(zeroconf, service_type, state_change, name):
        if name == registration_name:
            if state_change is ServiceStateChange.Added:
                service_added.set()
            elif state_change is ServiceStateChange.Removed:
                service_removed.set()

    zeroconf_browser = Zeroconf()
    browser = ServiceBrowser(zeroconf_browser, type_, [on_service_state_change])

    zeroconf_registrar = Zeroconf()
    desc = {'path': '/~paulsm/'}
    info = ServiceInfo(
        type_, registration_name,
        socket.inet_aton("10.0.1.2"), 80, 0, 0,
        desc, "ash-2.local.")
    zeroconf_registrar.register_service(info)

    try:
        service_added.wait(1)
        assert service_added.is_set()
        # Don't remove service, allow close() to cleanup

    finally:
        zeroconf_registrar.close()
        browser.cancel()
        zeroconf_browser.close()


def test_dnstext_repr_works():
    # There was an issue on Python 3 that prevented DNSText's repr
    # from working when the text was longer than 10 bytes
    text = DNSText('irrelevant', None, 0, 0, b'12345678901')
    repr(text)
