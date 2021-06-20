#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf.py """

import logging
import socket
import time
import unittest
import unittest.mock
from typing import Optional  # noqa # used in type hints

import zeroconf as r
from zeroconf import ServiceBrowser, ServiceInfo, Zeroconf, const

from . import _inject_response

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

        # we are going to patch the zeroconf send to check packet sizes
        old_send = zc.async_send

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

        # patch the zeroconf send
        with unittest.mock.patch.object(zc, "async_send", send):

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

            patch_warn = patch('zeroconf._logger.log.warning')
            patch_debug = patch('zeroconf._logger.log.debug')
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

            # mock the zeroconf logger and check for the correct logging backoff
            call_counts = mocked_log_warn.call_count, mocked_log_debug.call_count
            # force receive on oversized packet
            zc.send(out, const._MDNS_ADDR, const._MDNS_PORT)
            zc.send(out, const._MDNS_ADDR, const._MDNS_PORT)
            time.sleep(0.3)
            zeroconf.log.debug(
                'warn %d debug %d was %s',
                mocked_log_warn.call_count,
                mocked_log_debug.call_count,
                call_counts,
            )
            assert mocked_log_debug.call_count > call_counts[0]

        # close our zeroconf which will close the sockets
        zc.close()

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

        # Create a new object since allow_name_change will mutate the
        # original object and then we will have the wrong service
        # in the registry
        info_service2 = ServiceInfo(
            type_,
            '%s.%s' % (name, type_),
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )
        zc.register_service(info_service2, allow_name_change=True)
        assert info_service2.name.split('.')[0] == '%s-%d' % (name, number_hosts + 1)

    def generate_many_hosts(self, zc, type_, name, number_hosts):
        block_size = 25
        number_hosts = int(((number_hosts - 1) / block_size + 1)) * block_size
        for i in range(1, number_hosts + 1):
            next_name = name if i == 1 else '%s-%d' % (name, i)
            self.generate_host(zc, next_name, type_)

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
        _inject_response(zc, r.DNSIncoming(out.packets()[0]))
