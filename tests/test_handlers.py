#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf._handlers """

import asyncio
import logging
import pytest
import socket
import time
import unittest
import unittest.mock
from typing import List

import zeroconf as r
from zeroconf import ServiceInfo, Zeroconf, current_time_millis
from zeroconf import const
from zeroconf._dns import DNSRRSet
from zeroconf.asyncio import AsyncZeroconf


from . import _clear_cache, _inject_response

log = logging.getLogger('zeroconf')
original_logging_level = logging.NOTSET


def setup_module():
    global original_logging_level
    original_logging_level = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    if original_logging_level != logging.NOTSET:
        log.setLevel(original_logging_level)


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
        multicast_out = zc.query_handler.async_response(
            [r.DNSIncoming(packet) for packet in query.packets()], None, const._MDNS_PORT
        )[1]
        _process_outgoing_packet(multicast_out)

        # The additonals should all be suppresed since they are all in the answers section
        #
        assert nbr_answers == 4 and nbr_additionals == 0 and nbr_authorities == 0
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
        _process_outgoing_packet(
            zc.query_handler.async_response(
                [r.DNSIncoming(packet) for packet in query.packets()], None, const._MDNS_PORT
            )[1]
        )
        assert nbr_answers == 4 and nbr_additionals == 0 and nbr_authorities == 0
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

    # register
    zc.register_service(info)

    # Verify we won't respond for 1s with the same multicast
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    query.add_question(r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN))
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in query.packets()], None, const._MDNS_PORT
    )
    assert unicast_out is None
    assert multicast_out is None

    # Clear the cache to allow responding again
    _clear_cache(zc)

    # Verify we will now respond
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    query.add_question(r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN))
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in query.packets()], None, const._MDNS_PORT
    )
    assert multicast_out.id == query.id
    assert unicast_out is None
    assert multicast_out is not None
    has_srv = has_txt = has_a = False
    nbr_additionals = 0
    nbr_answers = len(multicast_out.answers)
    nbr_authorities = len(multicast_out.authorities)
    for answer in multicast_out.additionals:
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


def test_any_query_for_ptr():
    """Test that queries for ANY will return PTR records."""
    zc = Zeroconf(interfaces=['127.0.0.1'])
    type_ = "_anyptr._tcp.local."
    name = "knownname"
    registration_name = "%s.%s" % (name, type_)
    desc = {'path': '/~paulsm/'}
    server_name = "ash-2.local."
    ipv6_address = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    info = ServiceInfo(type_, registration_name, 80, 0, 0, desc, server_name, addresses=[ipv6_address])
    zc.registry.add(info)

    _clear_cache(zc)
    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(type_, const._TYPE_ANY, const._CLASS_IN)
    generated.add_question(question)
    packets = generated.packets()
    _, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert multicast_out.answers[0][0].name == type_
    assert multicast_out.answers[0][0].alias == registration_name
    # unregister
    zc.registry.remove(info)
    zc.close()


def test_aaaa_query():
    """Test that queries for AAAA records work."""
    zc = Zeroconf(interfaces=['127.0.0.1'])
    type_ = "_knownaaaservice._tcp.local."
    name = "knownname"
    registration_name = "%s.%s" % (name, type_)
    desc = {'path': '/~paulsm/'}
    server_name = "ash-2.local."
    ipv6_address = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    info = ServiceInfo(type_, registration_name, 80, 0, 0, desc, server_name, addresses=[ipv6_address])
    zc.registry.add(info)

    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(server_name, const._TYPE_AAAA, const._CLASS_IN)
    generated.add_question(question)
    packets = generated.packets()
    _, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert multicast_out.answers[0][0].address == ipv6_address
    # unregister
    zc.registry.remove(info)
    zc.close()


def test_a_and_aaaa_record_fate_sharing():
    """Test that queries for AAAA always return A records in the additionals."""
    zc = Zeroconf(interfaces=['127.0.0.1'])
    type_ = "_a-and-aaaa-service._tcp.local."
    name = "knownname"
    registration_name = "%s.%s" % (name, type_)
    desc = {'path': '/~paulsm/'}
    server_name = "ash-2.local."
    ipv6_address = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    ipv4_address = socket.inet_aton("10.0.1.2")
    info = ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, server_name, addresses=[ipv6_address, ipv4_address]
    )
    aaaa_record = info.dns_addresses(version=r.IPVersion.V6Only)[0]
    a_record = info.dns_addresses(version=r.IPVersion.V4Only)[0]

    zc.registry.add(info)

    # Test AAAA query
    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(server_name, const._TYPE_AAAA, const._CLASS_IN)
    generated.add_question(question)
    packets = generated.packets()
    _, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    answers = DNSRRSet([answer[0] for answer in multicast_out.answers])
    additionals = DNSRRSet(multicast_out.additionals)
    assert aaaa_record in answers
    assert a_record in additionals
    assert len(multicast_out.answers) == 1
    assert len(multicast_out.additionals) == 1

    # Test A query
    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(server_name, const._TYPE_A, const._CLASS_IN)
    generated.add_question(question)
    packets = generated.packets()
    _, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    answers = DNSRRSet([answer[0] for answer in multicast_out.answers])
    additionals = DNSRRSet(multicast_out.additionals)

    assert a_record in answers
    assert aaaa_record in additionals
    assert len(multicast_out.answers) == 1
    assert len(multicast_out.additionals) == 1
    # unregister
    zc.registry.remove(info)
    zc.close()


def test_unicast_response():
    """Ensure we send a unicast response when the source port is not the MDNS port."""
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
    # register
    zc.registry.add(info)
    _clear_cache(zc)

    # query
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    query.add_question(r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN))
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in query.packets()], "1.2.3.4", 1234
    )
    for out in (unicast_out, multicast_out):
        assert out.id == query.id
        has_srv = has_txt = has_a = False
        nbr_additionals = 0
        nbr_answers = len(out.answers)
        nbr_authorities = len(out.authorities)
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
    zc.registry.remove(info)
    zc.close()


def test_qu_response():
    """Handle multicast incoming with the QU bit set."""
    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=['127.0.0.1'])

    # service definition
    type_ = "_test-srvc-type._tcp.local."
    other_type_ = "_notthesame._tcp.local."
    name = "xxxyyy"
    registration_name = "%s.%s" % (name, type_)
    registration_name2 = "%s.%s" % (name, other_type_)
    desc = {'path': '/~paulsm/'}
    info = ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
    )
    info2 = ServiceInfo(
        other_type_,
        registration_name2,
        80,
        0,
        0,
        desc,
        "ash-other.local.",
        addresses=[socket.inet_aton("10.0.4.2")],
    )
    # register
    zc.register_service(info)

    def _validate_complete_response(query, out):
        assert out.id == query.id
        has_srv = has_txt = has_a = False
        nbr_additionals = 0
        nbr_answers = len(out.answers)
        nbr_authorities = len(out.authorities)
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

    # With QU should respond to only unicast when the answer has been recently multicast
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN)
    question.unicast = True  # Set the QU bit
    assert question.unicast is True
    query.add_question(question)

    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in query.packets()], "1.2.3.4", const._MDNS_PORT
    )
    assert multicast_out is None
    _validate_complete_response(query, unicast_out)

    _clear_cache(zc)
    # With QU should respond to only multicast since the response hasn't been seen since 75% of the ttl
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN)
    question.unicast = True  # Set the QU bit
    assert question.unicast is True
    query.add_question(question)
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in query.packets()], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    _validate_complete_response(query, multicast_out)

    # With QU set and an authorative answer (probe) should respond to both unitcast and multicast since the response hasn't been seen since 75% of the ttl
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN)
    question.unicast = True  # Set the QU bit
    assert question.unicast is True
    query.add_question(question)
    query.add_authorative_answer(info2.dns_pointer())
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in query.packets()], "1.2.3.4", const._MDNS_PORT
    )
    _validate_complete_response(query, unicast_out)
    _validate_complete_response(query, multicast_out)

    _inject_response(zc, r.DNSIncoming(multicast_out.packets()[0]))
    # With the cache repopulated; should respond to only unicast when the answer has been recently multicast
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN)
    question.unicast = True  # Set the QU bit
    assert question.unicast is True
    query.add_question(question)
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in query.packets()], "1.2.3.4", const._MDNS_PORT
    )
    assert multicast_out is None
    _validate_complete_response(query, unicast_out)
    # unregister
    zc.unregister_service(info)
    zc.close()


def test_known_answer_supression():
    zc = Zeroconf(interfaces=['127.0.0.1'])
    type_ = "_knownanswersv8._tcp.local."
    name = "knownname"
    registration_name = "%s.%s" % (name, type_)
    desc = {'path': '/~paulsm/'}
    server_name = "ash-2.local."
    info = ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, server_name, addresses=[socket.inet_aton("10.0.1.2")]
    )
    zc.registry.add(info)

    now = current_time_millis()
    _clear_cache(zc)
    # Test PTR supression
    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(type_, const._TYPE_PTR, const._CLASS_IN)
    generated.add_question(question)
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert multicast_out is not None and multicast_out.answers

    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(type_, const._TYPE_PTR, const._CLASS_IN)
    generated.add_question(question)
    generated.add_answer_at_time(info.dns_pointer(), now)
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    # If the answer is suppressed, the additional should be suppresed as well
    assert not multicast_out or not multicast_out.answers

    # Test A supression
    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(server_name, const._TYPE_A, const._CLASS_IN)
    generated.add_question(question)
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert multicast_out is not None and multicast_out.answers

    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(server_name, const._TYPE_A, const._CLASS_IN)
    generated.add_question(question)
    for dns_address in info.dns_addresses():
        generated.add_answer_at_time(dns_address, now)
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert not multicast_out or not multicast_out.answers

    # Test SRV supression
    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(registration_name, const._TYPE_SRV, const._CLASS_IN)
    generated.add_question(question)
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert multicast_out is not None and multicast_out.answers

    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(registration_name, const._TYPE_SRV, const._CLASS_IN)
    generated.add_question(question)
    generated.add_answer_at_time(info.dns_service(), now)
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    # If the answer is suppressed, the additional should be suppresed as well
    assert not multicast_out or not multicast_out.answers

    # Test TXT supression
    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(registration_name, const._TYPE_TXT, const._CLASS_IN)
    generated.add_question(question)
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert multicast_out is not None and multicast_out.answers

    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(registration_name, const._TYPE_TXT, const._CLASS_IN)
    generated.add_question(question)
    generated.add_answer_at_time(info.dns_text(), now)
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert not multicast_out or not multicast_out.answers

    # unregister
    zc.registry.remove(info)
    zc.close()


def test_multi_packet_known_answer_supression():
    zc = Zeroconf(interfaces=['127.0.0.1'])
    type_ = "_handlermultis._tcp.local."
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

    info = ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, server_name, addresses=[socket.inet_aton("10.0.1.2")]
    )
    info2 = ServiceInfo(
        type_, registration2_name, 80, 0, 0, desc, server_name2, addresses=[socket.inet_aton("10.0.1.2")]
    )
    info3 = ServiceInfo(
        type_, registration3_name, 80, 0, 0, desc, server_name3, addresses=[socket.inet_aton("10.0.1.2")]
    )
    zc.registry.add(info)
    zc.registry.add(info2)
    zc.registry.add(info3)

    now = current_time_millis()
    _clear_cache(zc)
    # Test PTR supression
    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(type_, const._TYPE_PTR, const._CLASS_IN)
    generated.add_question(question)
    for _ in range(1000):
        # Add so many answers we end up with another packet
        generated.add_answer_at_time(info.dns_pointer(), now)
    generated.add_answer_at_time(info2.dns_pointer(), now)
    generated.add_answer_at_time(info3.dns_pointer(), now)
    packets = generated.packets()
    assert len(packets) > 1
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert multicast_out is None
    # unregister
    zc.registry.remove(info)
    zc.registry.remove(info2)
    zc.registry.remove(info3)
    zc.close()


def test_known_answer_supression_service_type_enumeration_query():
    zc = Zeroconf(interfaces=['127.0.0.1'])
    type_ = "_otherknown._tcp.local."
    name = "knownname"
    registration_name = "%s.%s" % (name, type_)
    desc = {'path': '/~paulsm/'}
    server_name = "ash-2.local."
    info = ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, server_name, addresses=[socket.inet_aton("10.0.1.2")]
    )
    zc.registry.add(info)

    type_2 = "_otherknown2._tcp.local."
    name = "knownname"
    registration_name2 = "%s.%s" % (name, type_2)
    desc = {'path': '/~paulsm/'}
    server_name2 = "ash-3.local."
    info2 = ServiceInfo(
        type_2, registration_name2, 80, 0, 0, desc, server_name2, addresses=[socket.inet_aton("10.0.1.2")]
    )
    zc.registry.add(info2)
    now = current_time_millis()
    _clear_cache(zc)

    # Test PTR supression
    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(const._SERVICE_TYPE_ENUMERATION_NAME, const._TYPE_PTR, const._CLASS_IN)
    generated.add_question(question)
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert multicast_out is not None and multicast_out.answers

    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(const._SERVICE_TYPE_ENUMERATION_NAME, const._TYPE_PTR, const._CLASS_IN)
    generated.add_question(question)
    generated.add_answer_at_time(
        r.DNSPointer(
            const._SERVICE_TYPE_ENUMERATION_NAME,
            const._TYPE_PTR,
            const._CLASS_IN,
            const._DNS_OTHER_TTL,
            type_,
        ),
        now,
    )
    generated.add_answer_at_time(
        r.DNSPointer(
            const._SERVICE_TYPE_ENUMERATION_NAME,
            const._TYPE_PTR,
            const._CLASS_IN,
            const._DNS_OTHER_TTL,
            type_2,
        ),
        now,
    )
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert not multicast_out or not multicast_out.answers

    # unregister
    zc.registry.remove(info)
    zc.registry.remove(info2)
    zc.close()


# This test uses asyncio because it needs to access the cache directly
# which is not threadsafe
@pytest.mark.asyncio
async def test_qu_response_only_sends_additionals_if_sends_answer():
    """Test that a QU response does not send additionals unless it sends the answer as well."""
    # instantiate a zeroconf instance
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    zc = aiozc.zeroconf

    type_ = "_addtest1._tcp.local."
    name = "knownname"
    registration_name = "%s.%s" % (name, type_)
    desc = {'path': '/~paulsm/'}
    server_name = "ash-2.local."
    info = ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, server_name, addresses=[socket.inet_aton("10.0.1.2")]
    )
    zc.registry.add(info)

    type_2 = "_addtest2._tcp.local."
    name = "knownname"
    registration_name2 = "%s.%s" % (name, type_2)
    desc = {'path': '/~paulsm/'}
    server_name2 = "ash-3.local."
    info2 = ServiceInfo(
        type_2, registration_name2, 80, 0, 0, desc, server_name2, addresses=[socket.inet_aton("10.0.1.2")]
    )
    zc.registry.add(info2)

    ptr_record = info.dns_pointer()

    # Add the PTR record to the cache
    zc.cache.async_add_records([ptr_record])

    # Add the A record to the cache with 50% ttl remaining
    a_record = info.dns_addresses()[0]
    a_record.set_created_ttl(current_time_millis() - (a_record.ttl * 1000 / 2), a_record.ttl)
    assert not a_record.is_recent(current_time_millis())
    zc.cache.async_add_records([a_record])

    # With QU should respond to only unicast when the answer has been recently multicast
    # even if the additional has not been recently multicast
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN)
    question.unicast = True  # Set the QU bit
    assert question.unicast is True
    query.add_question(question)

    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in query.packets()], "1.2.3.4", const._MDNS_PORT
    )
    assert multicast_out is None
    assert a_record in unicast_out.additionals
    assert unicast_out.answers[0][0] == ptr_record

    # Remove the 50% A record and add a 100% A record
    zc.cache.async_remove_records([a_record])
    a_record = info.dns_addresses()[0]
    assert a_record.is_recent(current_time_millis())
    zc.cache.async_add_records([a_record])
    # With QU should respond to only unicast when the answer has been recently multicast
    # even if the additional has not been recently multicast
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN)
    question.unicast = True  # Set the QU bit
    assert question.unicast is True
    query.add_question(question)

    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in query.packets()], "1.2.3.4", const._MDNS_PORT
    )
    assert multicast_out is None
    assert a_record in unicast_out.additionals
    assert unicast_out.answers[0][0] == ptr_record

    # Remove the 100% PTR record and add a 50% PTR record
    zc.cache.async_remove_records([ptr_record])
    ptr_record.set_created_ttl(current_time_millis() - (ptr_record.ttl * 1000 / 2), ptr_record.ttl)
    assert not ptr_record.is_recent(current_time_millis())
    zc.cache.async_add_records([ptr_record])
    # With QU should respond to only multicast since the has less
    # than 75% of its ttl remaining
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN)
    question.unicast = True  # Set the QU bit
    assert question.unicast is True
    query.add_question(question)

    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in query.packets()], "1.2.3.4", const._MDNS_PORT
    )
    assert multicast_out.answers[0][0] == ptr_record
    assert a_record in multicast_out.additionals
    assert info.dns_text() in multicast_out.additionals
    assert info.dns_service() in multicast_out.additionals

    assert unicast_out is None

    # Ask 2 QU questions, with info the PTR is at 50%, with info2 the PTR is at 100%
    # We should get back a unicast reply for info2, but info should be multicasted since its within 75% of its TTL
    # With QU should respond to only multicast since the has less
    # than 75% of its ttl remaining
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN)
    question.unicast = True  # Set the QU bit
    assert question.unicast is True
    query.add_question(question)

    question = r.DNSQuestion(info2.type, const._TYPE_PTR, const._CLASS_IN)
    question.unicast = True  # Set the QU bit
    assert question.unicast is True
    query.add_question(question)
    zc.cache.async_add_records([info2.dns_pointer()])  # Add 100% TTL for info2 to the cache

    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in query.packets()], "1.2.3.4", const._MDNS_PORT
    )
    assert multicast_out.answers[0][0] == info.dns_pointer()
    assert info.dns_addresses()[0] in multicast_out.additionals
    assert info.dns_text() in multicast_out.additionals
    assert info.dns_service() in multicast_out.additionals

    assert unicast_out.answers[0][0] == info2.dns_pointer()
    assert info2.dns_addresses()[0] in unicast_out.additionals
    assert info2.dns_text() in unicast_out.additionals
    assert info2.dns_service() in unicast_out.additionals

    # unregister
    zc.registry.remove(info)
    await aiozc.async_close()


# This test uses asyncio because it needs to access the cache directly
# which is not threadsafe
@pytest.mark.asyncio
async def test_cache_flush_bit():
    """Test that the cache flush bit sets the TTL to one for matching records."""
    # instantiate a zeroconf instance
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    zc = aiozc.zeroconf

    type_ = "_cacheflush._tcp.local."
    name = "knownname"
    registration_name = "%s.%s" % (name, type_)
    desc = {'path': '/~paulsm/'}
    server_name = "server-uu1.local."
    info = ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, server_name, addresses=[socket.inet_aton("10.0.1.2")]
    )
    a_record = info.dns_addresses()[0]
    zc.cache.async_add_records([info.dns_pointer(), a_record, info.dns_text(), info.dns_service()])

    info.addresses = [socket.inet_aton("10.0.1.5"), socket.inet_aton("10.0.1.6")]
    new_records = info.dns_addresses()
    for new_record in new_records:
        assert new_record.unique is True

    original_a_record = zc.cache.async_get_unique(a_record)
    # Do the run within 1s to verify the original record is not going to be expired
    out = r.DNSOutgoing(const._FLAGS_QR_RESPONSE | const._FLAGS_AA, multicast=True)
    for answer in new_records:
        out.add_answer_at_time(answer, 0)
    for packet in out.packets():
        zc.record_manager.async_updates_from_response(r.DNSIncoming(packet))
    assert zc.cache.async_get_unique(a_record) is original_a_record
    assert original_a_record.ttl != 1
    for record in new_records:
        assert zc.cache.async_get_unique(record) is not None

    original_a_record.created = current_time_millis() - 1001

    # Do the run within 1s to verify the original record is not going to be expired
    out = r.DNSOutgoing(const._FLAGS_QR_RESPONSE | const._FLAGS_AA, multicast=True)
    for answer in new_records:
        out.add_answer_at_time(answer, 0)
    for packet in out.packets():
        zc.record_manager.async_updates_from_response(r.DNSIncoming(packet))
    assert original_a_record.ttl == 1
    for record in new_records:
        assert zc.cache.async_get_unique(record) is not None

    cached_records = [zc.cache.async_get_unique(record) for record in new_records]
    for record in cached_records:
        record.created = current_time_millis() - 1001

    fresh_address = socket.inet_aton("4.4.4.4")
    info.addresses = [fresh_address]
    # Do the run within 1s to verify the two new records get marked as expired
    out = r.DNSOutgoing(const._FLAGS_QR_RESPONSE | const._FLAGS_AA, multicast=True)
    for answer in info.dns_addresses():
        out.add_answer_at_time(answer, 0)
    for packet in out.packets():
        zc.record_manager.async_updates_from_response(r.DNSIncoming(packet))
    for record in cached_records:
        assert record.ttl == 1

    for entry in zc.cache.async_all_by_details(server_name, const._TYPE_A, const._CLASS_IN):
        if entry.address == fresh_address:
            assert entry.ttl > 1
        else:
            assert entry.ttl == 1

    # Wait for the ttl 1 records to expire
    await asyncio.sleep(1.1)

    loaded_info = r.ServiceInfo(type_, registration_name)
    loaded_info.load_from_cache(zc)
    assert loaded_info.addresses == info.addresses

    await aiozc.async_close()


# This test uses asyncio because it needs to access the cache directly
# which is not threadsafe
@pytest.mark.asyncio
async def test_record_update_manager_add_listener_callsback_existing_records():
    """Test that the RecordUpdateManager will callback existing records."""

    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    zc: Zeroconf = aiozc.zeroconf
    updated = []

    class MyListener(r.RecordUpdateListener):
        """A RecordUpdateListener that does not implement update_records."""

        def async_update_records(self, zc: 'Zeroconf', now: float, records: List[r.RecordUpdate]) -> None:
            """Update multiple records in one shot."""
            updated.extend(records)

    type_ = "_cacheflush._tcp.local."
    name = "knownname"
    registration_name = "%s.%s" % (name, type_)
    desc = {'path': '/~paulsm/'}
    server_name = "server-uu1.local."
    info = ServiceInfo(
        type_, registration_name, 80, 0, 0, desc, server_name, addresses=[socket.inet_aton("10.0.1.2")]
    )
    a_record = info.dns_addresses()[0]
    ptr_record = info.dns_pointer()
    zc.cache.async_add_records([ptr_record, a_record, info.dns_text(), info.dns_service()])

    listener = MyListener()

    zc.add_listener(
        listener,
        [
            r.DNSQuestion(type_, const._TYPE_PTR, const._CLASS_IN),
            r.DNSQuestion(server_name, const._TYPE_A, const._CLASS_IN),
        ],
    )
    await asyncio.sleep(0)  # flush out the call_soon_threadsafe

    assert set([record.new for record in updated]) == set([ptr_record, a_record])

    # The old records should be None so we trigger Add events
    # in service browsers instead of Update events
    assert set([record.old for record in updated]) == set([None])

    await aiozc.async_close()


@pytest.mark.asyncio
async def test_questions_query_handler_populates_the_question_history_from_qm_questions():
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    zc = aiozc.zeroconf
    now = current_time_millis()
    _clear_cache(zc)

    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion("_hap._tcp._local.", const._TYPE_PTR, const._CLASS_IN)
    question.unicast = False
    known_answer = r.DNSPointer(
        "_hap._tcp.local.", const._TYPE_PTR, const._CLASS_IN, 10000, 'known-to-other._hap._tcp.local.'
    )
    generated.add_question(question)
    generated.add_answer_at_time(known_answer, 0)
    now = r.current_time_millis()
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert multicast_out is None
    assert zc.question_history.suppresses(question, now, set([known_answer]))

    await aiozc.async_close()


@pytest.mark.asyncio
async def test_questions_query_handler_does_not_put_qu_questions_in_history():
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    zc = aiozc.zeroconf
    now = current_time_millis()
    _clear_cache(zc)

    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion("_hap._tcp._local.", const._TYPE_PTR, const._CLASS_IN)
    question.unicast = True
    known_answer = r.DNSPointer(
        "_hap._tcp.local.", const._TYPE_PTR, const._CLASS_IN, 10000, 'known-to-other._hap._tcp.local.'
    )
    generated.add_question(question)
    generated.add_answer_at_time(known_answer, 0)
    now = r.current_time_millis()
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.async_response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert multicast_out is None
    assert not zc.question_history.suppresses(question, now, set([known_answer]))

    await aiozc.async_close()


@pytest.mark.asyncio
async def test_guard_against_low_ptr_ttl():
    """Ensure we enforce a minimum for PTR record ttls to avoid excessive refresh queries from ServiceBrowsers.

    Some poorly designed IoT devices can set excessively low PTR
    TTLs would will cause ServiceBrowsers to flood the network
    with excessive refresh queries.
    """
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    zc = aiozc.zeroconf
    # Apple uses a 15s minimum TTL, however we do not have the same
    # level of rate limit and safe guards so we use 1/4 of the recommended value
    answer_with_low_ttl = r.DNSPointer(
        "myservicelow_tcp._tcp.local.",
        const._TYPE_PTR,
        const._CLASS_IN | const._CLASS_UNIQUE,
        2,
        'low.local.',
    )
    answer_with_normal_ttl = r.DNSPointer(
        "myservicelow_tcp._tcp.local.",
        const._TYPE_PTR,
        const._CLASS_IN | const._CLASS_UNIQUE,
        const._DNS_OTHER_TTL,
        'normal.local.',
    )
    good_bye_answer = r.DNSPointer(
        "myservicelow_tcp._tcp.local.",
        const._TYPE_PTR,
        const._CLASS_IN | const._CLASS_UNIQUE,
        0,
        'goodbye.local.',
    )
    # TTL should be adjusted to a safe value
    response = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    response.add_answer_at_time(answer_with_low_ttl, 0)
    response.add_answer_at_time(answer_with_normal_ttl, 0)
    response.add_answer_at_time(good_bye_answer, 0)
    incoming = r.DNSIncoming(response.packets()[0])
    zc.record_manager.async_updates_from_response(incoming)

    incoming_answer_low = zc.cache.async_get_unique(answer_with_low_ttl)
    assert incoming_answer_low.ttl == const._DNS_PTR_MIN_TTL
    incoming_answer_normal = zc.cache.async_get_unique(answer_with_normal_ttl)
    assert incoming_answer_normal.ttl == const._DNS_OTHER_TTL
    assert zc.cache.async_get_unique(good_bye_answer) is None
    await aiozc.async_close()
