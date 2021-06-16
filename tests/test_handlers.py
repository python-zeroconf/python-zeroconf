#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf._handlers """

import logging
import pytest
import socket
import time
import unittest
import unittest.mock

import zeroconf as r
from zeroconf import ServiceInfo, Zeroconf, current_time_millis
from zeroconf import const

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
        multicast_out = zc.query_handler.response(
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
            zc.query_handler.response(
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
    unicast_out, multicast_out = zc.query_handler.response(
        [r.DNSIncoming(packet) for packet in query.packets()], None, const._MDNS_PORT
    )
    assert unicast_out is None
    assert multicast_out is None

    # Clear the cache to allow responding again
    _clear_cache(zc)

    # Verify we will now respond
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    query.add_question(r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN))
    unicast_out, multicast_out = zc.query_handler.response(
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
    _, multicast_out = zc.query_handler.response(
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
    _, multicast_out = zc.query_handler.response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert multicast_out.answers[0][0].address == ipv6_address
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
    unicast_out, multicast_out = zc.query_handler.response(
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
    question.unique = True  # Set the QU bit
    assert question.unicast is True
    query.add_question(question)

    unicast_out, multicast_out = zc.query_handler.response(
        [r.DNSIncoming(packet) for packet in query.packets()], "1.2.3.4", const._MDNS_PORT
    )
    assert multicast_out is None
    _validate_complete_response(query, unicast_out)

    _clear_cache(zc)
    # With QU should respond to only multicast since the response hasn't been seen since 75% of the ttl
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN)
    question.unique = True  # Set the QU bit
    assert question.unicast is True
    query.add_question(question)
    unicast_out, multicast_out = zc.query_handler.response(
        [r.DNSIncoming(packet) for packet in query.packets()], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    _validate_complete_response(query, multicast_out)

    # With QU set and an authorative answer (probe) should respond to both unitcast and multicast since the response hasn't been seen since 75% of the ttl
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN)
    question.unique = True  # Set the QU bit
    assert question.unicast is True
    query.add_question(question)
    query.add_authorative_answer(info2.dns_pointer())
    unicast_out, multicast_out = zc.query_handler.response(
        [r.DNSIncoming(packet) for packet in query.packets()], "1.2.3.4", const._MDNS_PORT
    )
    _validate_complete_response(query, unicast_out)
    _validate_complete_response(query, multicast_out)

    _inject_response(zc, r.DNSIncoming(multicast_out.packets()[0]))
    # With the cache repopulated; should respond to only unicast when the answer has been recently multicast
    query = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(info.type, const._TYPE_PTR, const._CLASS_IN)
    question.unique = True  # Set the QU bit
    assert question.unicast is True
    query.add_question(question)
    unicast_out, multicast_out = zc.query_handler.response(
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
    unicast_out, multicast_out = zc.query_handler.response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert multicast_out is not None and multicast_out.answers

    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(type_, const._TYPE_PTR, const._CLASS_IN)
    generated.add_question(question)
    generated.add_answer_at_time(info.dns_pointer(), now)
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.response(
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
    unicast_out, multicast_out = zc.query_handler.response(
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
    unicast_out, multicast_out = zc.query_handler.response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert not multicast_out or not multicast_out.answers

    # Test SRV supression
    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(registration_name, const._TYPE_SRV, const._CLASS_IN)
    generated.add_question(question)
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert multicast_out is not None and multicast_out.answers

    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(registration_name, const._TYPE_SRV, const._CLASS_IN)
    generated.add_question(question)
    generated.add_answer_at_time(info.dns_service(), now)
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.response(
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
    unicast_out, multicast_out = zc.query_handler.response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert multicast_out is not None and multicast_out.answers

    generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
    question = r.DNSQuestion(registration_name, const._TYPE_TXT, const._CLASS_IN)
    generated.add_question(question)
    generated.add_answer_at_time(info.dns_text(), now)
    packets = generated.packets()
    unicast_out, multicast_out = zc.query_handler.response(
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
    unicast_out, multicast_out = zc.query_handler.response(
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
    unicast_out, multicast_out = zc.query_handler.response(
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
    unicast_out, multicast_out = zc.query_handler.response(
        [r.DNSIncoming(packet) for packet in packets], "1.2.3.4", const._MDNS_PORT
    )
    assert unicast_out is None
    assert not multicast_out or not multicast_out.answers

    # unregister
    zc.registry.remove(info)
    zc.registry.remove(info2)
    zc.close()
