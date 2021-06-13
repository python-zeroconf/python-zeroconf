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
from zeroconf import const
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
        hinfo = DNSHinfo('irrelevant', const._TYPE_HINFO, 0, 0, 'cpu', 'os')
        assert hinfo == hinfo
        repr(hinfo)

    def test_dns_pointer_repr(self):
        pointer = r.DNSPointer('irrelevant', const._TYPE_PTR, const._CLASS_IN, const._DNS_OTHER_TTL, '123')
        repr(pointer)

    def test_dns_address_repr(self):
        address = r.DNSAddress('irrelevant', const._TYPE_SOA, const._CLASS_IN, 1, b'a')
        assert repr(address).endswith("b'a'")

        address_ipv4 = r.DNSAddress(
            'irrelevant', const._TYPE_SOA, const._CLASS_IN, 1, socket.inet_pton(socket.AF_INET, '127.0.0.1')
        )
        assert repr(address_ipv4).endswith('127.0.0.1')

        address_ipv6 = r.DNSAddress(
            'irrelevant', const._TYPE_SOA, const._CLASS_IN, 1, socket.inet_pton(socket.AF_INET6, '::1')
        )
        assert repr(address_ipv6).endswith('::1')

    def test_dns_question_repr(self):
        question = r.DNSQuestion('irrelevant', const._TYPE_SRV, const._CLASS_IN | const._CLASS_UNIQUE)
        repr(question)
        assert not question != question

    def test_dns_service_repr(self):
        service = r.DNSService(
            'irrelevant', const._TYPE_SRV, const._CLASS_IN, const._DNS_HOST_TTL, 0, 0, 80, 'a'
        )
        repr(service)

    def test_dns_record_abc(self):
        record = r.DNSRecord('irrelevant', const._TYPE_SRV, const._CLASS_IN, const._DNS_HOST_TTL)
        self.assertRaises(r.AbstractMethodException, record.__eq__, record)
        self.assertRaises(r.AbstractMethodException, record.write, None)

    def test_dns_record_reset_ttl(self):
        record = r.DNSRecord('irrelevant', const._TYPE_SRV, const._CLASS_IN, const._DNS_HOST_TTL)
        time.sleep(1)
        record2 = r.DNSRecord('irrelevant', const._TYPE_SRV, const._CLASS_IN, const._DNS_HOST_TTL)
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
        dns_outgoing = r.DNSOutgoing(const._FLAGS_QR_QUERY)
        repr(dns_outgoing)


class PacketGeneration(unittest.TestCase):
    def test_parse_own_packet_simple(self):
        generated = r.DNSOutgoing(0)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_simple_unicast(self):
        generated = r.DNSOutgoing(0, False)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_flags(self):
        generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_question(self):
        generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
        generated.add_question(r.DNSQuestion("testname.local.", const._TYPE_SRV, const._CLASS_IN))
        r.DNSIncoming(generated.packet())

    def test_parse_own_packet_response(self):
        generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
        generated.add_answer_at_time(
            r.DNSService(
                "æøå.local.",
                const._TYPE_SRV,
                const._CLASS_IN | const._CLASS_UNIQUE,
                const._DNS_HOST_TTL,
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
        generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
        question = r.DNSQuestion("testname.local.", const._TYPE_SRV, const._CLASS_IN)
        generated.add_question(question)
        parsed = r.DNSIncoming(generated.packet())
        assert len(generated.questions) == 1
        assert len(generated.questions) == len(parsed.questions)
        assert question == parsed.questions[0]

    def test_suppress_answer(self):
        query_generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
        question = r.DNSQuestion("testname.local.", const._TYPE_SRV, const._CLASS_IN)
        query_generated.add_question(question)
        answer1 = r.DNSService(
            "testname1.local.",
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            const._DNS_HOST_TTL,
            0,
            0,
            80,
            "foo.local.",
        )
        staleanswer2 = r.DNSService(
            "testname2.local.",
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            const._DNS_HOST_TTL / 2,
            0,
            0,
            80,
            "foo.local.",
        )
        answer2 = r.DNSService(
            "testname2.local.",
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            const._DNS_HOST_TTL,
            0,
            0,
            80,
            "foo.local.",
        )
        query_generated.add_answer_at_time(answer1, 0)
        query_generated.add_answer_at_time(staleanswer2, 0)
        query = r.DNSIncoming(query_generated.packet())

        # Should be suppressed
        response = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
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
        tmp.type = const._TYPE_A
        response.add_answer(query, tmp)
        assert len(response.answers) == 3

        # Should not be suppressed, class is different
        tmp = copy.copy(answer1)
        tmp.class_ = const._CLASS_NONE
        response.add_answer(query, tmp)
        assert len(response.answers) == 4

        # ::TODO:: could add additional tests for DNSAddress, DNSHinfo, DNSPointer, DNSText, DNSService

    def test_dns_hinfo(self):
        generated = r.DNSOutgoing(0)
        generated.add_additional_answer(DNSHinfo('irrelevant', const._TYPE_HINFO, 0, 0, 'cpu', 'os'))
        parsed = r.DNSIncoming(generated.packet())
        answer = cast(r.DNSHinfo, parsed.answers[0])
        assert answer.cpu == u'cpu'
        assert answer.os == u'os'

        generated = r.DNSOutgoing(0)
        generated.add_additional_answer(DNSHinfo('irrelevant', const._TYPE_HINFO, 0, 0, 'cpu', 'x' * 257))
        self.assertRaises(r.NamePartTooLongException, generated.packet)

    def test_many_questions(self):
        """Test many questions get seperated into multiple packets."""
        generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
        questions = []
        for i in range(100):
            question = r.DNSQuestion(f"testname{i}.local.", const._TYPE_SRV, const._CLASS_IN)
            generated.add_question(question)
            questions.append(question)
        assert len(generated.questions) == 100

        packets = generated.packets()
        assert len(packets) == 2
        assert len(packets[0]) < const._MAX_MSG_TYPICAL
        assert len(packets[1]) < const._MAX_MSG_TYPICAL

        parsed1 = r.DNSIncoming(packets[0])
        assert len(parsed1.questions) == 85
        parsed2 = r.DNSIncoming(packets[1])
        assert len(parsed2.questions) == 15

    def test_only_one_answer_can_by_large(self):
        """Test that only the first answer in each packet can be large.

        https://datatracker.ietf.org/doc/html/rfc6762#section-17
        """
        generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
        query = r.DNSIncoming(r.DNSOutgoing(const._FLAGS_QR_QUERY).packet())
        for i in range(3):
            generated.add_answer(
                query,
                r.DNSText(
                    "zoom._hap._tcp.local.",
                    const._TYPE_TXT,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    1200,
                    b'\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==' * 100,
                ),
            )
        generated.add_answer(
            query,
            r.DNSService(
                "testname1.local.",
                const._TYPE_SRV,
                const._CLASS_IN | const._CLASS_UNIQUE,
                const._DNS_HOST_TTL,
                0,
                0,
                80,
                "foo.local.",
            ),
        )
        assert len(generated.answers) == 4

        packets = generated.packets()
        assert len(packets) == 4
        assert len(packets[0]) <= const._MAX_MSG_ABSOLUTE
        assert len(packets[0]) > const._MAX_MSG_TYPICAL

        assert len(packets[1]) <= const._MAX_MSG_ABSOLUTE
        assert len(packets[1]) > const._MAX_MSG_TYPICAL

        assert len(packets[2]) <= const._MAX_MSG_ABSOLUTE
        assert len(packets[2]) > const._MAX_MSG_TYPICAL

        assert len(packets[3]) <= const._MAX_MSG_TYPICAL

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

        generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
        for i in range(35):
            question = r.DNSQuestion(f"testname{i}.local.", const._TYPE_SRV, const._CLASS_IN)
            generated.add_question(question)
            answer = r.DNSService(
                f"testname{i}.local.",
                const._TYPE_SRV,
                const._CLASS_IN | const._CLASS_UNIQUE,
                const._DNS_HOST_TTL,
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
        assert len(packets[0]) <= const._MAX_MSG_TYPICAL
        assert len(packets[1]) <= const._MAX_MSG_TYPICAL

        parsed1 = r.DNSIncoming(packets[0])
        assert len(parsed1.questions) == 35
        assert len(parsed1.answers) == 33

        parsed2 = r.DNSIncoming(packets[1])
        assert len(parsed2.questions) == 0
        assert len(parsed2.answers) == 2


class PacketForm(unittest.TestCase):
    def test_transaction_id(self):
        """ID must be zero in a DNS-SD packet"""
        generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
        bytes = generated.packet()
        id = bytes[0] << 8 | bytes[1]
        assert id == 0

    def test_query_header_bits(self):
        generated = r.DNSOutgoing(const._FLAGS_QR_QUERY)
        bytes = generated.packet()
        flags = bytes[2] << 8 | bytes[3]
        assert flags == 0x0

    def test_response_header_bits(self):
        generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
        bytes = generated.packet()
        flags = bytes[2] << 8 | bytes[3]
        assert flags == 0x8000

    def test_numbers(self):
        generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
        bytes = generated.packet()
        (num_questions, num_answers, num_authorities, num_additionals) = struct.unpack('!4H', bytes[4:12])
        assert num_questions == 0
        assert num_answers == 0
        assert num_authorities == 0
        assert num_additionals == 0

    def test_numbers_questions(self):
        generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
        question = r.DNSQuestion("testname.local.", const._TYPE_SRV, const._CLASS_IN)
        for i in range(10):
            generated.add_question(question)
        bytes = generated.packet()
        (num_questions, num_answers, num_authorities, num_additionals) = struct.unpack('!4H', bytes[4:12])
        assert num_questions == 10
        assert num_answers == 0
        assert num_authorities == 0
        assert num_additionals == 0


class TestDnsIncoming(unittest.TestCase):
    def test_incoming_exception_handling(self):
        generated = r.DNSOutgoing(0)
        packet = generated.packet()
        packet = packet[:8] + b'deadbeef' + packet[8:]
        parsed = r.DNSIncoming(packet)
        parsed = r.DNSIncoming(packet)
        assert parsed.valid is False

    def test_incoming_unknown_type(self):
        generated = r.DNSOutgoing(0)
        answer = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'a')
        generated.add_additional_answer(answer)
        packet = generated.packet()
        parsed = r.DNSIncoming(packet)
        assert len(parsed.answers) == 0
        assert parsed.is_query() != parsed.is_response()

    def test_incoming_ipv6(self):
        addr = "2606:2800:220:1:248:1893:25c8:1946"  # example.com
        packed = socket.inet_pton(socket.AF_INET6, addr)
        generated = r.DNSOutgoing(0)
        answer = r.DNSAddress('domain', const._TYPE_AAAA, const._CLASS_IN | const._CLASS_UNIQUE, 1, packed)
        generated.add_additional_answer(answer)
        packet = generated.packet()
        parsed = r.DNSIncoming(packet)
        record = parsed.answers[0]
        assert isinstance(record, r.DNSAddress)
        assert record.address == packed


class TestDNSCache(unittest.TestCase):
    def test_order(self):
        record1 = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'a')
        record2 = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'b')
        cache = r.DNSCache()
        cache.add(record1)
        cache.add(record2)
        entry = r.DNSEntry('a', const._TYPE_SOA, const._CLASS_IN)
        cached_record = cache.get(entry)
        assert cached_record == record2

    def test_cache_empty_does_not_leak_memory_by_leaving_empty_list(self):
        record1 = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'a')
        record2 = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'b')
        cache = r.DNSCache()
        cache.add(record1)
        cache.add(record2)
        assert 'a' in cache.cache
        cache.remove(record1)
        cache.remove(record2)
        assert 'a' not in cache.cache

    def test_cache_empty_multiple_calls_does_not_throw(self):
        record1 = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'a')
        record2 = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'b')
        cache = r.DNSCache()
        cache.add(record1)
        cache.add(record2)
        assert 'a' in cache.cache
        cache.remove(record1)
        cache.remove(record2)
        # Ensure multiple removes does not throw
        cache.remove(record1)
        cache.remove(record2)
        assert 'a' not in cache.cache


def test_dns_compression_rollback_for_corruption():
    """Verify rolling back does not lead to dns compression corruption."""
    out = r.DNSOutgoing(const._FLAGS_QR_RESPONSE | const._FLAGS_AA)
    address = socket.inet_pton(socket.AF_INET, "192.168.208.5")

    additionals = [
        {
            "name": "HASS Bridge ZJWH FF5137._hap._tcp.local.",
            "address": address,
            "port": 51832,
            "text": b"\x13md=HASS Bridge"
            b" ZJWH\x06pv=1.0\x14id=01:6B:30:FF:51:37\x05c#=12\x04s#=1\x04ff=0\x04"
            b"ci=2\x04sf=0\x0bsh=L0m/aQ==",
        },
        {
            "name": "HASS Bridge 3K9A C2582A._hap._tcp.local.",
            "address": address,
            "port": 51834,
            "text": b"\x13md=HASS Bridge"
            b" 3K9A\x06pv=1.0\x14id=E2:AA:5B:C2:58:2A\x05c#=12\x04s#=1\x04ff=0\x04"
            b"ci=2\x04sf=0\x0bsh=b2CnzQ==",
        },
        {
            "name": "Master Bed TV CEDB27._hap._tcp.local.",
            "address": address,
            "port": 51830,
            "text": b"\x10md=Master Bed"
            b" TV\x06pv=1.0\x14id=9E:B7:44:CE:DB:27\x05c#=18\x04s#=1\x04ff=0\x05"
            b"ci=31\x04sf=0\x0bsh=CVj1kw==",
        },
        {
            "name": "Living Room TV 921B77._hap._tcp.local.",
            "address": address,
            "port": 51833,
            "text": b"\x11md=Living Room"
            b" TV\x06pv=1.0\x14id=11:61:E7:92:1B:77\x05c#=17\x04s#=1\x04ff=0\x05"
            b"ci=31\x04sf=0\x0bsh=qU77SQ==",
        },
        {
            "name": "HASS Bridge ZC8X FF413D._hap._tcp.local.",
            "address": address,
            "port": 51829,
            "text": b"\x13md=HASS Bridge"
            b" ZC8X\x06pv=1.0\x14id=96:14:45:FF:41:3D\x05c#=12\x04s#=1\x04ff=0\x04"
            b"ci=2\x04sf=0\x0bsh=b0QZlg==",
        },
        {
            "name": "HASS Bridge WLTF 4BE61F._hap._tcp.local.",
            "address": address,
            "port": 51837,
            "text": b"\x13md=HASS Bridge"
            b" WLTF\x06pv=1.0\x14id=E0:E7:98:4B:E6:1F\x04c#=2\x04s#=1\x04ff=0\x04"
            b"ci=2\x04sf=0\x0bsh=ahAISA==",
        },
        {
            "name": "FrontdoorCamera 8941D1._hap._tcp.local.",
            "address": address,
            "port": 54898,
            "text": b"\x12md=FrontdoorCamera\x06pv=1.0\x14id=9F:B7:DC:89:41:D1\x04c#=2\x04"
            b"s#=1\x04ff=0\x04ci=2\x04sf=0\x0bsh=0+MXmA==",
        },
        {
            "name": "HASS Bridge W9DN 5B5CC5._hap._tcp.local.",
            "address": address,
            "port": 51836,
            "text": b"\x13md=HASS Bridge"
            b" W9DN\x06pv=1.0\x14id=11:8E:DB:5B:5C:C5\x05c#=12\x04s#=1\x04ff=0\x04"
            b"ci=2\x04sf=0\x0bsh=6fLM5A==",
        },
        {
            "name": "HASS Bridge Y9OO EFF0A7._hap._tcp.local.",
            "address": address,
            "port": 51838,
            "text": b"\x13md=HASS Bridge"
            b" Y9OO\x06pv=1.0\x14id=D3:FE:98:EF:F0:A7\x04c#=2\x04s#=1\x04ff=0\x04"
            b"ci=2\x04sf=0\x0bsh=u3bdfw==",
        },
        {
            "name": "Snooze Room TV 6B89B0._hap._tcp.local.",
            "address": address,
            "port": 51835,
            "text": b"\x11md=Snooze Room"
            b" TV\x06pv=1.0\x14id=5F:D5:70:6B:89:B0\x05c#=17\x04s#=1\x04ff=0\x05"
            b"ci=31\x04sf=0\x0bsh=xNTqsg==",
        },
        {
            "name": "AlexanderHomeAssistant 74651D._hap._tcp.local.",
            "address": address,
            "port": 54811,
            "text": b"\x19md=AlexanderHomeAssistant\x06pv=1.0\x14id=59:8A:0B:74:65:1D\x05"
            b"c#=14\x04s#=1\x04ff=0\x04ci=2\x04sf=0\x0bsh=ccZLPA==",
        },
        {
            "name": "HASS Bridge OS95 39C053._hap._tcp.local.",
            "address": address,
            "port": 51831,
            "text": b"\x13md=HASS Bridge"
            b" OS95\x06pv=1.0\x14id=7E:8C:E6:39:C0:53\x05c#=12\x04s#=1\x04ff=0\x04ci=2"
            b"\x04sf=0\x0bsh=Xfe5LQ==",
        },
    ]

    out.add_answer_at_time(
        DNSText(
            "HASS Bridge W9DN 5B5CC5._hap._tcp.local.",
            const._TYPE_TXT,
            const._CLASS_IN | const._CLASS_UNIQUE,
            const._DNS_OTHER_TTL,
            b'\x13md=HASS Bridge W9DN\x06pv=1.0\x14id=11:8E:DB:5B:5C:C5\x05c#=12\x04s#=1'
            b'\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==',
        ),
        0,
    )

    for record in additionals:
        out.add_additional_answer(
            r.DNSService(
                record["name"],  # type: ignore
                const._TYPE_SRV,
                const._CLASS_IN | const._CLASS_UNIQUE,
                const._DNS_HOST_TTL,
                0,
                0,
                record["port"],  # type: ignore
                record["name"],  # type: ignore
            )
        )
        out.add_additional_answer(
            r.DNSText(
                record["name"],  # type: ignore
                const._TYPE_TXT,
                const._CLASS_IN | const._CLASS_UNIQUE,
                const._DNS_OTHER_TTL,
                record["text"],  # type: ignore
            )
        )
        out.add_additional_answer(
            r.DNSAddress(
                record["name"],  # type: ignore
                const._TYPE_A,
                const._CLASS_IN | const._CLASS_UNIQUE,
                const._DNS_HOST_TTL,
                record["address"],  # type: ignore
            )
        )

    for packet in out.packets():
        # Verify we can process the packets we created to
        # ensure there is no corruption with the dns compression
        incoming = r.DNSIncoming(packet)
        assert incoming.valid is True


def test_tc_bit_in_query_packet():
    """Verify the TC bit is set when known answers exceed the packet size."""
    out = r.DNSOutgoing(const._FLAGS_QR_QUERY | const._FLAGS_AA)
    type_ = "_hap._tcp.local."
    out.add_question(r.DNSQuestion(type_, const._TYPE_PTR, const._CLASS_IN))

    for i in range(30):
        out.add_answer_at_time(
            DNSText(
                ("HASS Bridge W9DN %s._hap._tcp.local." % i),
                const._TYPE_TXT,
                const._CLASS_IN | const._CLASS_UNIQUE,
                const._DNS_OTHER_TTL,
                b'\x13md=HASS Bridge W9DN\x06pv=1.0\x14id=11:8E:DB:5B:5C:C5\x05c#=12\x04s#=1'
                b'\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==',
            ),
            0,
        )

    packets = out.packets()
    assert len(packets) == 3

    first_packet = r.DNSIncoming(packets[0])
    assert first_packet.flags & const._FLAGS_TC == const._FLAGS_TC
    assert first_packet.valid is True

    second_packet = r.DNSIncoming(packets[1])
    assert second_packet.flags & const._FLAGS_TC == const._FLAGS_TC
    assert second_packet.valid is True

    third_packet = r.DNSIncoming(packets[2])
    assert third_packet.flags & const._FLAGS_TC == 0
    assert third_packet.valid is True


def test_tc_bit_not_set_in_answer_packet():
    """Verify the TC bit is not set when there are no questions and answers exceed the packet size."""
    out = r.DNSOutgoing(const._FLAGS_QR_RESPONSE | const._FLAGS_AA)
    for i in range(30):
        out.add_answer_at_time(
            DNSText(
                ("HASS Bridge W9DN %s._hap._tcp.local." % i),
                const._TYPE_TXT,
                const._CLASS_IN | const._CLASS_UNIQUE,
                const._DNS_OTHER_TTL,
                b'\x13md=HASS Bridge W9DN\x06pv=1.0\x14id=11:8E:DB:5B:5C:C5\x05c#=12\x04s#=1'
                b'\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==',
            ),
            0,
        )

    packets = out.packets()
    assert len(packets) == 3

    first_packet = r.DNSIncoming(packets[0])
    assert first_packet.flags & const._FLAGS_TC == 0
    assert first_packet.valid is True

    second_packet = r.DNSIncoming(packets[1])
    assert second_packet.flags & const._FLAGS_TC == 0
    assert second_packet.valid is True

    third_packet = r.DNSIncoming(packets[2])
    assert third_packet.flags & const._FLAGS_TC == 0
    assert third_packet.valid is True
