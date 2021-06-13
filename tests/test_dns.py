#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf.py """

import copy
import logging
import socket
import struct
import time
import unittest
import unittest.mock
from typing import Dict, cast  # noqa # used in type hints

import zeroconf as r
from zeroconf import (
    DNSHinfo,
    DNSText,
    ServiceInfo,
)

log = logging.getLogger('zeroconf')
original_logging_level = logging.NOTSET


def setup_module():
    global original_logging_level
    original_logging_level = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    if original_logging_level != logging.NOTSET:
        log.setLevel(original_logging_level)


class TestDunder(unittest.TestCase):
    def test_dns_text_repr(self):
        # There was an issue on Python 3 that prevented DNSText's repr
        # from working when the text was longer than 10 bytes
        text = DNSText('irrelevant', 0, 0, 0, b'12345678901')
        repr(text)

        text = DNSText('irrelevant', 0, 0, 0, b'123')
        repr(text)

    def test_dns_hinfo_repr_eq(self):
        hinfo = DNSHinfo('irrelevant', r._TYPE_HINFO, 0, 0, 'cpu', 'os')
        assert hinfo == hinfo
        repr(hinfo)

    def test_dns_pointer_repr(self):
        pointer = r.DNSPointer('irrelevant', r._TYPE_PTR, r._CLASS_IN, r._DNS_OTHER_TTL, '123')
        repr(pointer)

    def test_dns_address_repr(self):
        address = r.DNSAddress('irrelevant', r._TYPE_SOA, r._CLASS_IN, 1, b'a')
        assert repr(address).endswith("b'a'")

        address_ipv4 = r.DNSAddress(
            'irrelevant', r._TYPE_SOA, r._CLASS_IN, 1, socket.inet_pton(socket.AF_INET, '127.0.0.1')
        )
        assert repr(address_ipv4).endswith('127.0.0.1')

        address_ipv6 = r.DNSAddress(
            'irrelevant', r._TYPE_SOA, r._CLASS_IN, 1, socket.inet_pton(socket.AF_INET6, '::1')
        )
        assert repr(address_ipv6).endswith('::1')

    def test_dns_question_repr(self):
        question = r.DNSQuestion('irrelevant', r._TYPE_SRV, r._CLASS_IN | r._CLASS_UNIQUE)
        repr(question)
        assert not question != question

    def test_dns_service_repr(self):
        service = r.DNSService('irrelevant', r._TYPE_SRV, r._CLASS_IN, r._DNS_HOST_TTL, 0, 0, 80, 'a')
        repr(service)

    def test_dns_record_abc(self):
        record = r.DNSRecord('irrelevant', r._TYPE_SRV, r._CLASS_IN, r._DNS_HOST_TTL)
        self.assertRaises(r.AbstractMethodException, record.__eq__, record)
        self.assertRaises(r.AbstractMethodException, record.write, None)

    def test_dns_record_reset_ttl(self):
        record = r.DNSRecord('irrelevant', r._TYPE_SRV, r._CLASS_IN, r._DNS_HOST_TTL)
        time.sleep(1)
        record2 = r.DNSRecord('irrelevant', r._TYPE_SRV, r._CLASS_IN, r._DNS_HOST_TTL)
        now = r.current_time_millis()

        assert record.created != record2.created
        assert record.get_remaining_ttl(now) != record2.get_remaining_ttl(now)

        record.reset_ttl(record2)

        assert record.ttl == record2.ttl
        assert record.created == record2.created
        assert record.get_remaining_ttl(now) == record2.get_remaining_ttl(now)

    def test_service_info_dunder(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            b'',
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )

        assert not info != info
        repr(info)

    def test_service_info_text_properties_not_given(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)
        info = ServiceInfo(
            type_=type_,
            name=registration_name,
            addresses=[socket.inet_aton("10.0.1.2")],
            port=80,
            server="ash-2.local.",
        )

        assert isinstance(info.text, bytes)
        repr(info)

    def test_dns_outgoing_repr(self):
        dns_outgoing = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        repr(dns_outgoing)


class PacketGeneration(unittest.TestCase):
    def test_parse_own_packet_simple(self):
        generated = r.DNSOutgoing(0)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_simple_unicast(self):
        generated = r.DNSOutgoing(0, False)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_flags(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_question(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        generated.add_question(r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN))
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_response(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        generated.add_answer_at_time(
            r.DNSService(
                "æøå.local.",
                r._TYPE_SRV,
                r._CLASS_IN | r._CLASS_UNIQUE,
                r._DNS_HOST_TTL,
                0,
                0,
                80,
                "foo.local.",
            ),
            0,
        )
        parsed = r.DNSIncoming(generated.packet())
        assert len(generated.answers) == 1
        assert len(generated.answers) == len(parsed.answers)

    def test_match_question(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        question = r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN)
        generated.add_question(question)
        parsed = r.DNSIncoming(generated.packet())
        assert len(generated.questions) == 1
        assert len(generated.questions) == len(parsed.questions)
        assert question == parsed.questions[0]

    def test_suppress_answer(self):
        query_generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        question = r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN)
        query_generated.add_question(question)
        answer1 = r.DNSService(
            "testname1.local.",
            r._TYPE_SRV,
            r._CLASS_IN | r._CLASS_UNIQUE,
            r._DNS_HOST_TTL,
            0,
            0,
            80,
            "foo.local.",
        )
        staleanswer2 = r.DNSService(
            "testname2.local.",
            r._TYPE_SRV,
            r._CLASS_IN | r._CLASS_UNIQUE,
            r._DNS_HOST_TTL / 2,
            0,
            0,
            80,
            "foo.local.",
        )
        answer2 = r.DNSService(
            "testname2.local.",
            r._TYPE_SRV,
            r._CLASS_IN | r._CLASS_UNIQUE,
            r._DNS_HOST_TTL,
            0,
            0,
            80,
            "foo.local.",
        )
        query_generated.add_answer_at_time(answer1, 0)
        query_generated.add_answer_at_time(staleanswer2, 0)
        query = r.DNSIncoming(query_generated.packet())

        # Should be suppressed
        response = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        response.add_answer(query, answer1)
        assert len(response.answers) == 0

        # Should not be suppressed, TTL in query is too short
        response.add_answer(query, answer2)
        assert len(response.answers) == 1

        # Should not be suppressed, name is different
        tmp = copy.copy(answer1)
        tmp.key = "testname3.local."
        tmp.name = "testname3.local."
        response.add_answer(query, tmp)
        assert len(response.answers) == 2

        # Should not be suppressed, type is different
        tmp = copy.copy(answer1)
        tmp.type = r._TYPE_A
        response.add_answer(query, tmp)
        assert len(response.answers) == 3

        # Should not be suppressed, class is different
        tmp = copy.copy(answer1)
        tmp.class_ = r._CLASS_NONE
        response.add_answer(query, tmp)
        assert len(response.answers) == 4

        # ::TODO:: could add additional tests for DNSAddress, DNSHinfo, DNSPointer, DNSText, DNSService

    def test_dns_hinfo(self):
        generated = r.DNSOutgoing(0)
        generated.add_additional_answer(DNSHinfo('irrelevant', r._TYPE_HINFO, 0, 0, 'cpu', 'os'))
        parsed = r.DNSIncoming(generated.packet())
        answer = cast(r.DNSHinfo, parsed.answers[0])
        assert answer.cpu == u'cpu'
        assert answer.os == u'os'

        generated = r.DNSOutgoing(0)
        generated.add_additional_answer(DNSHinfo('irrelevant', r._TYPE_HINFO, 0, 0, 'cpu', 'x' * 257))
        self.assertRaises(r.NamePartTooLongException, generated.packet)

    def test_many_questions(self):
        """Test many questions get seperated into multiple packets."""
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        questions = []
        for i in range(100):
            question = r.DNSQuestion(f"testname{i}.local.", r._TYPE_SRV, r._CLASS_IN)
            generated.add_question(question)
            questions.append(question)
        assert len(generated.questions) == 100

        packets = generated.packets()
        assert len(packets) == 2
        assert len(packets[0]) < r._MAX_MSG_TYPICAL
        assert len(packets[1]) < r._MAX_MSG_TYPICAL

        parsed1 = r.DNSIncoming(packets[0])
        assert len(parsed1.questions) == 85
        parsed2 = r.DNSIncoming(packets[1])
        assert len(parsed2.questions) == 15

    def test_only_one_answer_can_by_large(self):
        """Test that only the first answer in each packet can be large.

        https://datatracker.ietf.org/doc/html/rfc6762#section-17
        """
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        query = r.DNSIncoming(r.DNSOutgoing(r._FLAGS_QR_QUERY).packet())
        for i in range(3):
            generated.add_answer(
                query,
                r.DNSText(
                    "zoom._hap._tcp.local.",
                    r._TYPE_TXT,
                    r._CLASS_IN | r._CLASS_UNIQUE,
                    1200,
                    b'\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==' * 100,
                ),
            )
        generated.add_answer(
            query,
            r.DNSService(
                "testname1.local.",
                r._TYPE_SRV,
                r._CLASS_IN | r._CLASS_UNIQUE,
                r._DNS_HOST_TTL,
                0,
                0,
                80,
                "foo.local.",
            ),
        )
        assert len(generated.answers) == 4

        packets = generated.packets()
        assert len(packets) == 4
        assert len(packets[0]) <= r._MAX_MSG_ABSOLUTE
        assert len(packets[0]) > r._MAX_MSG_TYPICAL

        assert len(packets[1]) <= r._MAX_MSG_ABSOLUTE
        assert len(packets[1]) > r._MAX_MSG_TYPICAL

        assert len(packets[2]) <= r._MAX_MSG_ABSOLUTE
        assert len(packets[2]) > r._MAX_MSG_TYPICAL

        assert len(packets[3]) <= r._MAX_MSG_TYPICAL

        for packet in packets:
            parsed = r.DNSIncoming(packet)
            assert len(parsed.answers) == 1

    def test_questions_do_not_end_up_every_packet(self):
        """Test that questions are not sent again when multiple packets are needed.

        https://datatracker.ietf.org/doc/html/rfc6762#section-7.2
        Sometimes a Multicast DNS querier will already have too many answers
        to fit in the Known-Answer Section of its query packets....  It MUST
        immediately follow the packet with another query packet containing no
        questions and as many more Known-Answer records as will fit.
        """

        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        for i in range(35):
            question = r.DNSQuestion(f"testname{i}.local.", r._TYPE_SRV, r._CLASS_IN)
            generated.add_question(question)
            answer = r.DNSService(
                f"testname{i}.local.",
                r._TYPE_SRV,
                r._CLASS_IN | r._CLASS_UNIQUE,
                r._DNS_HOST_TTL,
                0,
                0,
                80,
                f"foo{i}.local.",
            )
            generated.add_answer_at_time(answer, 0)

        assert len(generated.questions) == 35
        assert len(generated.answers) == 35

        packets = generated.packets()
        assert len(packets) == 2
        assert len(packets[0]) <= r._MAX_MSG_TYPICAL
        assert len(packets[1]) <= r._MAX_MSG_TYPICAL

        parsed1 = r.DNSIncoming(packets[0])
        assert len(parsed1.questions) == 35
        assert len(parsed1.answers) == 33

        parsed2 = r.DNSIncoming(packets[1])
        assert len(parsed2.questions) == 0
        assert len(parsed2.answers) == 2


class PacketForm(unittest.TestCase):
    def test_transaction_id(self):
        """ID must be zero in a DNS-SD packet"""
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        bytes = generated.packet()
        id = bytes[0] << 8 | bytes[1]
        assert id == 0

    def test_query_header_bits(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_QUERY)
        bytes = generated.packet()
        flags = bytes[2] << 8 | bytes[3]
        assert flags == 0x0

    def test_response_header_bits(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        bytes = generated.packet()
        flags = bytes[2] << 8 | bytes[3]
        assert flags == 0x8000

    def test_numbers(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        bytes = generated.packet()
        (num_questions, num_answers, num_authorities, num_additionals) = struct.unpack('!4H', bytes[4:12])
        assert num_questions == 0
        assert num_answers == 0
        assert num_authorities == 0
        assert num_additionals == 0

    def test_numbers_questions(self):
        generated = r.DNSOutgoing(r._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion("testname.local.", r._TYPE_SRV, r._CLASS_IN)
        for i in range(10):
            generated.add_question(question)
        bytes = generated.packet()
        (num_questions, num_answers, num_authorities, num_additionals) = struct.unpack('!4H', bytes[4:12])
        assert num_questions == 10
        assert num_answers == 0
        assert num_authorities == 0
        assert num_additionals == 0
