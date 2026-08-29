"""Unit tests for zeroconf._services.info."""

from __future__ import annotations

import asyncio
import logging
import os
import socket
import threading
import time
import unittest
from collections.abc import Callable
from ipaddress import ip_address
from threading import Event
from unittest.mock import patch

import pytest

import zeroconf as r
from zeroconf import DNSAddress, RecordUpdate, const
from zeroconf._protocol.outgoing import DNSOutgoing
from zeroconf._services import info
from zeroconf._services.info import ServiceInfo, _has_more_scope_info
from zeroconf._utils.ipaddress import ZeroconfIPv4Address
from zeroconf._utils.net import IPVersion
from zeroconf.asyncio import AsyncZeroconf

from .. import QUICK_REQUEST_TIMEOUT_MS, _inject_response, has_working_ipv6, mock_incoming_msg

log = logging.getLogger("zeroconf")
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
        desc = {"path": "/~paulsm/"}
        service_name = "name._type._tcp.local."
        service_type = "_type._tcp.local."
        service_server = "ash-1.local."
        service_address = socket.inet_aton("10.0.1.2")
        info = ServiceInfo(
            service_type,
            service_name,
            22,
            0,
            0,
            desc,
            service_server,
            addresses=[service_address],
        )
        assert info.get_name() == "name"

    def test_service_info_rejects_non_matching_updates(self):
        """Verify records with the wrong name are rejected."""

        zc = r.Zeroconf(interfaces=["127.0.0.1"])
        desc = {"path": "/~paulsm/"}
        service_name = "name._type._tcp.local."
        service_type = "_type._tcp.local."
        service_server = "ash-1.local."
        service_address = socket.inet_aton("10.0.1.2")
        ttl = 120
        now = r.current_time_millis()
        info = ServiceInfo(
            service_type,
            service_name,
            22,
            0,
            0,
            desc,
            service_server,
            addresses=[service_address],
        )
        # Verify backwards compatibility with calling with None
        info.async_update_records(zc, now, [])
        # Matching updates
        info.async_update_records(
            zc,
            now,
            [
                RecordUpdate(
                    r.DNSText(
                        service_name,
                        const._TYPE_TXT,
                        const._CLASS_IN | const._CLASS_UNIQUE,
                        ttl,
                        b"\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==",
                    ),
                    None,
                )
            ],
        )
        assert info.properties[b"ci"] == b"2"
        info.async_update_records(
            zc,
            now,
            [
                RecordUpdate(
                    r.DNSService(
                        service_name,
                        const._TYPE_SRV,
                        const._CLASS_IN | const._CLASS_UNIQUE,
                        ttl,
                        0,
                        0,
                        80,
                        "ASH-2.local.",
                    ),
                    None,
                )
            ],
        )
        assert info.server_key == "ash-2.local."
        assert info.server == "ASH-2.local."
        new_address = socket.inet_aton("10.0.1.3")
        info.async_update_records(
            zc,
            now,
            [
                RecordUpdate(
                    r.DNSAddress(
                        "ASH-2.local.",
                        const._TYPE_A,
                        const._CLASS_IN | const._CLASS_UNIQUE,
                        ttl,
                        new_address,
                    ),
                    None,
                )
            ],
        )
        assert new_address in info.addresses
        # Non-matching updates
        info.async_update_records(
            zc,
            now,
            [
                RecordUpdate(
                    r.DNSText(
                        "incorrect.name.",
                        const._TYPE_TXT,
                        const._CLASS_IN | const._CLASS_UNIQUE,
                        ttl,
                        b"\x04ff=0\x04ci=3\x04sf=0\x0bsh=6fLM5A==",
                    ),
                    None,
                )
            ],
        )
        assert info.properties[b"ci"] == b"2"
        info.async_update_records(
            zc,
            now,
            [
                RecordUpdate(
                    r.DNSService(
                        "incorrect.name.",
                        const._TYPE_SRV,
                        const._CLASS_IN | const._CLASS_UNIQUE,
                        ttl,
                        0,
                        0,
                        80,
                        "ASH-2.local.",
                    ),
                    None,
                )
            ],
        )
        assert info.server_key == "ash-2.local."
        assert info.server == "ASH-2.local."
        new_address = socket.inet_aton("10.0.1.4")
        info.async_update_records(
            zc,
            now,
            [
                RecordUpdate(
                    r.DNSAddress(
                        "incorrect.name.",
                        const._TYPE_A,
                        const._CLASS_IN | const._CLASS_UNIQUE,
                        ttl,
                        new_address,
                    ),
                    None,
                )
            ],
        )
        assert new_address not in info.addresses
        zc.close()

    def test_service_info_rejects_expired_records(self):
        """Verify records that are expired are rejected."""
        zc = r.Zeroconf(interfaces=["127.0.0.1"])
        desc = {"path": "/~paulsm/"}
        service_name = "name._type._tcp.local."
        service_type = "_type._tcp.local."
        service_server = "ash-1.local."
        service_address = socket.inet_aton("10.0.1.2")
        ttl = 120
        now = r.current_time_millis()
        info = ServiceInfo(
            service_type,
            service_name,
            22,
            0,
            0,
            desc,
            service_server,
            addresses=[service_address],
        )
        # Matching updates
        info.async_update_records(
            zc,
            now,
            [
                RecordUpdate(
                    r.DNSText(
                        service_name,
                        const._TYPE_TXT,
                        const._CLASS_IN | const._CLASS_UNIQUE,
                        ttl,
                        b"\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==",
                    ),
                    None,
                )
            ],
        )
        assert info.properties[b"ci"] == b"2"
        # Expired record
        expired_record = r.DNSText(
            service_name,
            const._TYPE_TXT,
            const._CLASS_IN | const._CLASS_UNIQUE,
            ttl,
            b"\x04ff=0\x04ci=3\x04sf=0\x0bsh=6fLM5A==",
        )
        zc.cache._async_set_created_ttl(expired_record, 1000, 1)
        info.async_update_records(zc, now, [RecordUpdate(expired_record, None)])
        assert info.properties[b"ci"] == b"2"
        zc.close()

    @unittest.skipIf(not has_working_ipv6(), "Requires IPv6")
    @unittest.skipIf(os.environ.get("SKIP_IPV6"), "IPv6 tests disabled")
    @pytest.mark.usefixtures("quick_request_timing")
    def test_get_info_partial(self):
        zc = r.Zeroconf(interfaces=["127.0.0.1"])

        service_name = "name._type._tcp.local."
        service_type = "_type._tcp.local."
        service_server = "ash-1.local."
        service_text = b"path=/~matt1/"
        service_address = "10.0.1.2"
        service_address_v6_ll = "fe80::52e:c2f2:bc5f:e9c6"
        service_scope_id = 12

        service_info = None
        send_event = Event()
        service_info_event = Event()

        last_sent: r.DNSOutgoing | None = None

        def send(out, addr=const._MDNS_ADDR, port=const._MDNS_PORT, v6_flow_scope=()):
            nonlocal last_sent

            last_sent = out
            send_event.set()

        # patch the zeroconf send
        with patch.object(zc, "async_send", send):

            def get_service_info_helper(zc, type, name):
                nonlocal service_info
                service_info = zc.get_service_info(type, name, timeout=10000)
                service_info_event.set()

            try:
                ttl = 120
                helper_thread = threading.Thread(
                    target=get_service_info_helper,
                    args=(zc, service_type, service_name),
                )
                helper_thread.start()
                # Covers the ~1s duplicate-question interval when a query
                # generated from the pre-inject cache burns a slot.
                wait_time = 2

                # Expect query for SRV, TXT, A, AAAA
                send_event.wait(wait_time)
                assert last_sent is not None
                assert len(last_sent.questions) == 4
                assert r.DNSQuestion(service_name, const._TYPE_SRV, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_TXT, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_A, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_AAAA, const._CLASS_IN) in last_sent.questions
                assert service_info is None

                # Expect query for SRV, A, AAAA
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
                # Clear only after the inject has been processed on the
                # loop so a query built from the pre-inject cache cannot
                # satisfy the wait below.
                last_sent = None
                send_event.clear()
                send_event.wait(wait_time)
                assert last_sent is not None
                assert len(last_sent.questions) == 3  # type: ignore[unreachable]
                assert r.DNSQuestion(service_name, const._TYPE_SRV, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_A, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_AAAA, const._CLASS_IN) in last_sent.questions
                assert service_info is None

                # Expect query for A, AAAA
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
                last_sent = None
                send_event.clear()
                send_event.wait(wait_time)
                assert last_sent is not None
                assert len(last_sent.questions) == 2
                assert r.DNSQuestion(service_server, const._TYPE_A, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_server, const._TYPE_AAAA, const._CLASS_IN) in last_sent.questions
                last_sent = None
                assert service_info is None

                # Expect no further queries
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
                            ),
                            r.DNSAddress(
                                service_server,
                                const._TYPE_AAAA,
                                const._CLASS_IN | const._CLASS_UNIQUE,
                                ttl,
                                socket.inet_pton(socket.AF_INET6, service_address_v6_ll),
                                scope_id=service_scope_id,
                            ),
                        ]
                    ),
                )
                last_sent = None
                send_event.clear()
                service_info_event.wait(wait_time)
                assert last_sent is None
                assert service_info is not None

            finally:
                helper_thread.join()
                zc.remove_all_service_listeners()
                zc.close()

    @unittest.skipIf(not has_working_ipv6(), "Requires IPv6")
    @unittest.skipIf(os.environ.get("SKIP_IPV6"), "IPv6 tests disabled")
    def test_get_info_suppressed_by_question_history(self):
        zc = r.Zeroconf(interfaces=["127.0.0.1"])

        service_name = "name._type._tcp.local."
        service_type = "_type._tcp.local."

        service_info = None
        send_event = Event()
        service_info_event = Event()

        last_sent: r.DNSOutgoing | None = None

        def send(out, addr=const._MDNS_ADDR, port=const._MDNS_PORT, v6_flow_scope=()):
            nonlocal last_sent

            last_sent = out
            send_event.set()

        # patch the zeroconf send
        with patch.object(zc, "async_send", send):

            def get_service_info_helper(zc, type, name, timeout):
                nonlocal service_info
                service_info = zc.get_service_info(type, name, timeout)
                service_info_event.set()

            try:
                # Seed TXT/A/AAAA with a far-future `than` before the
                # helper thread starts. The first (QU) query bypasses
                # suppression so phase 1 still observes 4 questions; the
                # second (QM) query fires ~220-320ms after the first, too
                # tight a window to seed reliably from the test thread on
                # slow runners. async_expire only removes entries where
                # now - than > _DUPLICATE_QUESTION_INTERVAL, so future-
                # dated entries persist for the duration of the test.
                seed_history_questions = (
                    r.DNSQuestion(service_name, const._TYPE_A, const._CLASS_IN),
                    r.DNSQuestion(service_name, const._TYPE_AAAA, const._CLASS_IN),
                    r.DNSQuestion(service_name, const._TYPE_TXT, const._CLASS_IN),
                )
                far_future = r.current_time_millis() + 60_000
                for question in seed_history_questions:
                    zc.question_history.add_question_at_time(question, far_future, set())

                # No answers ever come back (all queries are suppressed),
                # so cap the helper at the worst-case sum of the three
                # phase waits below plus margin instead of the 3000ms
                # default. Phase 3 waits ~1.6s (the 999ms QM gap plus
                # jitter and 500ms buffer); 1500ms covers it.
                helper_thread = threading.Thread(
                    target=get_service_info_helper,
                    args=(zc, service_type, service_name, 1500),
                )
                helper_thread.start()
                wait_time = (const._LISTENER_TIME + info._AVOID_SYNC_DELAY_RANDOM_INTERVAL[1] + 500) / 1000

                # Expect query for SRV, TXT, A, AAAA
                send_event.wait(wait_time)
                assert last_sent is not None
                assert len(last_sent.questions) == 4
                assert r.DNSQuestion(service_name, const._TYPE_SRV, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_TXT, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_A, const._CLASS_IN) in last_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_AAAA, const._CLASS_IN) in last_sent.questions
                assert service_info is None

                # Expect query for SRV only as A, AAAA, and TXT are suppressed
                # by the question history
                last_sent = None
                send_event.clear()
                send_event.wait(wait_time)
                assert last_sent is not None
                assert len(last_sent.questions) == 1  # type: ignore[unreachable]
                assert r.DNSQuestion(service_name, const._TYPE_SRV, const._CLASS_IN) in last_sent.questions
                assert service_info is None

                # Future-date SRV too: the SRV entry added by the previous
                # QM query has `than = now`, so it expires after
                # _DUPLICATE_QUESTION_INTERVAL — before the next scheduled
                # QM query (~1s + jitter later).
                zc.question_history.add_question_at_time(
                    r.DNSQuestion(service_name, const._TYPE_SRV, const._CLASS_IN),
                    r.current_time_millis() + 60_000,
                    set(),
                )

                wait_time = (
                    const._DUPLICATE_QUESTION_INTERVAL + info._AVOID_SYNC_DELAY_RANDOM_INTERVAL[1] + 500
                ) / 1000
                # Expect no queries as all are suppressed by the question history
                last_sent = None
                send_event.clear()
                send_event.wait(wait_time)
                # All questions are suppressed so no query should be sent
                assert last_sent is None
                assert service_info is None

            finally:
                helper_thread.join()
                zc.remove_all_service_listeners()
                zc.close()

    @pytest.mark.usefixtures("quick_request_timing")
    def test_get_info_single(self):
        zc = r.Zeroconf(interfaces=["127.0.0.1"])

        service_name = "name._type._tcp.local."
        service_type = "_type._tcp.local."
        service_server = "ash-1.local."
        service_text = b"path=/~matt1/"
        service_address = "10.0.1.2"

        service_info = None
        service_info_event = Event()

        ttl = 120
        response_records = [
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

        sent_queries: list[r.DNSOutgoing] = []

        def send(out, addr=const._MDNS_ADDR, port=const._MDNS_PORT, v6_flow_scope=()):
            """Capture each query and, on the first one, fill the cache
            inline so the next iteration of `async_request` finds
            `_is_complete=True` and exits without sending another query.

            Running the inject from inside `send` keeps it on the event
            loop thread and atomic with the first send — eliminating the
            test-thread → `run_coroutine_threadsafe` race that flaked
            under PyPy + use_cython when `quick_request_timing` shortens
            the inter-iteration delay to ~15ms.
            """
            sent_queries.append(out)
            if len(sent_queries) == 1:
                zc.record_manager.async_updates_from_response(mock_incoming_msg(response_records))

        def get_service_info_helper(zc, type, name):
            nonlocal service_info
            service_info = zc.get_service_info(type, name)
            service_info_event.set()

        # patch the zeroconf send
        with patch.object(zc, "async_send", send):
            try:
                helper_thread = threading.Thread(
                    target=get_service_info_helper,
                    args=(zc, service_type, service_name),
                )
                helper_thread.start()

                # Helper should complete promptly — the inline inject in
                # `send` populates the cache before the request loop's
                # next iteration.
                service_info_event.wait(1)
                assert service_info is not None

                # First (and only) query: QU for SRV/TXT/A/AAAA.
                assert len(sent_queries) == 1
                first_sent = sent_queries[0]
                assert len(first_sent.questions) == 4
                assert r.DNSQuestion(service_name, const._TYPE_SRV, const._CLASS_IN) in first_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_TXT, const._CLASS_IN) in first_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_A, const._CLASS_IN) in first_sent.questions
                assert r.DNSQuestion(service_name, const._TYPE_AAAA, const._CLASS_IN) in first_sent.questions

            finally:
                helper_thread.join()
                zc.remove_all_service_listeners()
                zc.close()

    def test_service_info_duplicate_properties_txt_records(self):
        """Verify the first property is always used when there are duplicates in a txt record."""

        zc = r.Zeroconf(interfaces=["127.0.0.1"])
        desc = {"path": "/~paulsm/"}
        service_name = "name._type._tcp.local."
        service_type = "_type._tcp.local."
        service_server = "ash-1.local."
        service_address = socket.inet_aton("10.0.1.2")
        ttl = 120
        now = r.current_time_millis()
        info = ServiceInfo(
            service_type,
            service_name,
            22,
            0,
            0,
            desc,
            service_server,
            addresses=[service_address],
        )
        info.async_update_records(
            zc,
            now,
            [
                r.RecordUpdate(
                    r.DNSText(
                        service_name,
                        const._TYPE_TXT,
                        const._CLASS_IN | const._CLASS_UNIQUE,
                        ttl,
                        b"\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==\x04dd=0\x04jl=2\x04qq=0\x0brr=6fLM5A==\x04ci=3",
                    ),
                    None,
                )
            ],
        )
        assert info.properties[b"dd"] == b"0"
        assert info.properties[b"jl"] == b"2"
        assert info.properties[b"ci"] == b"2"
        zc.close()

    def test_service_info_empty_value_txt_record(self):
        """Verify `key=` decodes to an empty value, not to a valueless `key`."""
        zc = r.Zeroconf(interfaces=["127.0.0.1"])
        service_name = "name._type._tcp.local."
        service_type = "_type._tcp.local."
        service_server = "ash-1.local."
        text = b"\x03rm=\x02rs\x05ve=05"
        info = ServiceInfo(
            service_type,
            service_name,
            22,
            0,
            0,
            {"path": "/~paulsm/"},
            service_server,
            addresses=[socket.inet_aton("10.0.1.2")],
        )
        info.async_update_records(
            zc,
            r.current_time_millis(),
            [
                r.RecordUpdate(
                    r.DNSText(
                        service_name,
                        const._TYPE_TXT,
                        const._CLASS_IN | const._CLASS_UNIQUE,
                        120,
                        text,
                    ),
                    None,
                )
            ],
        )
        assert info.properties[b"rm"] == b""
        assert info.properties[b"rs"] is None
        assert info.properties[b"ve"] == b"05"

        # The string-facing API must preserve the distinction too.
        assert info.decoded_properties["rm"] == ""
        assert info.decoded_properties["rs"] is None
        assert info.decoded_properties["ve"] == "05"

        # Re-encoding either view of the properties must reproduce the received rdata.
        for properties in (info.properties, info.decoded_properties):
            assert (
                ServiceInfo(
                    service_type,
                    service_name,
                    22,
                    0,
                    0,
                    properties,
                    service_server,
                ).text
                == text
            )
        zc.close()


def test_multiple_addresses():
    type_ = "_http._tcp.local."
    registration_name = f"xxxyyy.{type_}"
    desc = {"path": "/~paulsm/"}
    address_parsed = "10.0.1.2"
    address = socket.inet_aton(address_parsed)

    # New kwarg way
    info = ServiceInfo(
        type_,
        registration_name,
        80,
        0,
        0,
        desc,
        "ash-2.local.",
        addresses=[address, address],
    )

    assert info.addresses == [address, address]
    assert info.parsed_addresses() == [address_parsed, address_parsed]
    assert info.parsed_scoped_addresses() == [address_parsed, address_parsed]

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
    assert info.parsed_addresses() == [address_parsed, address_parsed]
    assert info.parsed_scoped_addresses() == [address_parsed, address_parsed]

    if has_working_ipv6() and not os.environ.get("SKIP_IPV6"):
        address_v6_parsed = "2001:db8::1"
        address_v6 = socket.inet_pton(socket.AF_INET6, address_v6_parsed)
        address_v6_ll_parsed = "fe80::52e:c2f2:bc5f:e9c6"
        address_v6_ll_scoped_parsed = "fe80::52e:c2f2:bc5f:e9c6%12"
        address_v6_ll = socket.inet_pton(socket.AF_INET6, address_v6_ll_parsed)
        interface_index = 12
        infos = [
            ServiceInfo(
                type_,
                registration_name,
                80,
                0,
                0,
                desc,
                "ash-2.local.",
                addresses=[address, address_v6, address_v6_ll],
                interface_index=interface_index,
            ),
            ServiceInfo(
                type_,
                registration_name,
                80,
                0,
                0,
                desc,
                "ash-2.local.",
                parsed_addresses=[
                    address_parsed,
                    address_v6_parsed,
                    address_v6_ll_parsed,
                ],
                interface_index=interface_index,
            ),
        ]
        for info in infos:
            assert info.addresses == [address]
            assert info.addresses_by_version(r.IPVersion.All) == [
                address,
                address_v6,
                address_v6_ll,
            ]
            assert info.ip_addresses_by_version(r.IPVersion.All) == [
                ip_address(address),
                ip_address(address_v6),
                ip_address(address_v6_ll_scoped_parsed),
            ]
            assert info.addresses_by_version(r.IPVersion.V4Only) == [address]
            assert info.ip_addresses_by_version(r.IPVersion.V4Only) == [ip_address(address)]
            assert info.addresses_by_version(r.IPVersion.V6Only) == [
                address_v6,
                address_v6_ll,
            ]
            assert info.ip_addresses_by_version(r.IPVersion.V6Only) == [
                ip_address(address_v6),
                ip_address(address_v6_ll_scoped_parsed),
            ]
            assert info.parsed_addresses() == [
                address_parsed,
                address_v6_parsed,
                address_v6_ll_parsed,
            ]
            assert info.parsed_addresses(r.IPVersion.V4Only) == [address_parsed]
            assert info.parsed_addresses(r.IPVersion.V6Only) == [
                address_v6_parsed,
                address_v6_ll_parsed,
            ]
            assert info.parsed_scoped_addresses() == [
                address_parsed,
                address_v6_parsed,
                address_v6_ll_scoped_parsed,
            ]
            assert info.parsed_scoped_addresses(r.IPVersion.V4Only) == [address_parsed]
            assert info.parsed_scoped_addresses(r.IPVersion.V6Only) == [
                address_v6_parsed,
                address_v6_ll_scoped_parsed,
            ]


def test_scoped_addresses_from_cache():
    type_ = "_http._tcp.local."
    registration_name = f"scoped.{type_}"
    zeroconf = r.Zeroconf(interfaces=["127.0.0.1"])
    host = "scoped.local."

    zeroconf.cache.async_add_records(
        [
            r.DNSPointer(
                type_,
                const._TYPE_PTR,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                registration_name,
            ),
            r.DNSService(
                registration_name,
                const._TYPE_SRV,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                0,
                0,
                80,
                host,
            ),
            r.DNSAddress(
                host,
                const._TYPE_AAAA,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                socket.inet_pton(socket.AF_INET6, "fe80::52e:c2f2:bc5f:e9c6"),
                scope_id=12,
            ),
        ]
    )

    # New kwarg way
    info = ServiceInfo(type_, registration_name)
    info.load_from_cache(zeroconf)
    assert info.parsed_scoped_addresses() == ["fe80::52e:c2f2:bc5f:e9c6%12"]
    assert info.ip_addresses_by_version(r.IPVersion.V6Only) == [ip_address("fe80::52e:c2f2:bc5f:e9c6%12")]
    zeroconf.close()


def test_scoped_address_preferred_when_unscoped_arrives_first_in_cache():
    """A scoped AAAA in the cache wins over an earlier unscoped copy of the same address."""
    type_ = "_http._tcp.local."
    registration_name = f"scoped-first.{type_}"
    zeroconf = r.Zeroconf(interfaces=["127.0.0.1"])
    host = "scoped-first.local."
    packed = socket.inet_pton(socket.AF_INET6, "fe80::52e:c2f2:bc5f:e9c6")

    zeroconf.cache.async_add_records(
        [
            r.DNSPointer(
                type_,
                const._TYPE_PTR,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                registration_name,
            ),
            r.DNSService(
                registration_name,
                const._TYPE_SRV,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                0,
                0,
                80,
                host,
            ),
            r.DNSAddress(
                host,
                const._TYPE_AAAA,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                packed,
                scope_id=None,
            ),
            r.DNSAddress(
                host,
                const._TYPE_AAAA,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                packed,
                scope_id=7,
            ),
        ]
    )

    info = ServiceInfo(type_, registration_name)
    info.load_from_cache(zeroconf)
    assert info.parsed_scoped_addresses() == ["fe80::52e:c2f2:bc5f:e9c6%7"]
    assert info.ip_addresses_by_version(r.IPVersion.V6Only) == [ip_address("fe80::52e:c2f2:bc5f:e9c6%7")]
    zeroconf.close()


@pytest.mark.asyncio
async def test_scoped_address_replaces_unscoped_in_live_update():
    """A late-arriving scoped AAAA replaces a previously-stored unscoped variant."""
    type_ = "_http._tcp.local."
    registration_name = f"scoped-live.{type_}"
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    host = "scoped-live.local."
    packed = socket.inet_pton(socket.AF_INET6, "fe80::52e:c2f2:bc5f:e9c6")

    info = ServiceInfo(type_, registration_name, server=host)
    now = r.current_time_millis()
    unscoped = r.DNSAddress(
        host,
        const._TYPE_AAAA,
        const._CLASS_IN | const._CLASS_UNIQUE,
        120,
        packed,
        scope_id=None,
    )
    scoped = r.DNSAddress(
        host,
        const._TYPE_AAAA,
        const._CLASS_IN | const._CLASS_UNIQUE,
        120,
        packed,
        scope_id=9,
    )
    info.async_update_records(aiozc.zeroconf, now, [RecordUpdate(unscoped, None)])
    assert info.parsed_scoped_addresses() == ["fe80::52e:c2f2:bc5f:e9c6"]
    info.async_update_records(aiozc.zeroconf, now, [RecordUpdate(scoped, unscoped)])
    assert info.parsed_scoped_addresses() == ["fe80::52e:c2f2:bc5f:e9c6%9"]
    await aiozc.async_close()


def test_scoped_address_kept_when_unscoped_arrives_after_in_cache():
    """Scoped AAAA seen first in iteration keeps its scope when an unscoped duplicate follows."""
    type_ = "_http._tcp.local."
    registration_name = f"scoped-after.{type_}"
    zeroconf = r.Zeroconf(interfaces=["127.0.0.1"])
    host = "scoped-after.local."
    packed = socket.inet_pton(socket.AF_INET6, "fe80::52e:c2f2:bc5f:e9c6")

    zeroconf.cache.async_add_records(
        [
            r.DNSPointer(
                type_,
                const._TYPE_PTR,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                registration_name,
            ),
            r.DNSService(
                registration_name,
                const._TYPE_SRV,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                0,
                0,
                80,
                host,
            ),
            r.DNSAddress(
                host,
                const._TYPE_AAAA,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                packed,
                scope_id=5,
            ),
            r.DNSAddress(
                host,
                const._TYPE_AAAA,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                packed,
                scope_id=None,
            ),
        ]
    )

    info = ServiceInfo(type_, registration_name)
    info.load_from_cache(zeroconf)
    assert info.parsed_scoped_addresses() == ["fe80::52e:c2f2:bc5f:e9c6%5"]
    assert info.ip_addresses_by_version(r.IPVersion.V6Only) == [ip_address("fe80::52e:c2f2:bc5f:e9c6%5")]
    zeroconf.close()


def test_has_more_scope_info_returns_false_for_ipv4():
    """The scope_id helper short-circuits for IPv4 since A records carry no scope."""
    ip4 = ZeroconfIPv4Address("192.0.2.1")
    assert _has_more_scope_info(ip4, ip4) is False


def test_scope_upgrade_preserves_lifo_recency_order():
    """A scoped AAAA that upgrades an earlier entry becomes the most recent in LIFO order."""
    type_ = "_http._tcp.local."
    registration_name = f"reorder.{type_}"
    zeroconf = r.Zeroconf(interfaces=["127.0.0.1"])
    host = "reorder.local."
    link_local = socket.inet_pton(socket.AF_INET6, "fe80::52e:c2f2:bc5f:e9c6")
    ula = socket.inet_pton(socket.AF_INET6, "fdc8:d776:7cca:46ed::2")

    zeroconf.cache.async_add_records(
        [
            r.DNSPointer(
                type_,
                const._TYPE_PTR,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                registration_name,
            ),
            r.DNSService(
                registration_name,
                const._TYPE_SRV,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                0,
                0,
                80,
                host,
            ),
            r.DNSAddress(
                host,
                const._TYPE_AAAA,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                link_local,
                scope_id=None,
            ),
            r.DNSAddress(
                host,
                const._TYPE_AAAA,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                ula,
                scope_id=None,
            ),
            r.DNSAddress(
                host,
                const._TYPE_AAAA,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                link_local,
                scope_id=11,
            ),
        ]
    )

    info = ServiceInfo(type_, registration_name)
    info.load_from_cache(zeroconf)
    # The scoped link-local upgrade is the most recent observation, so it
    # has to come first in LIFO order, ahead of the earlier unrelated ULA.
    assert info.ip_addresses_by_version(r.IPVersion.V6Only) == [
        ip_address("fe80::52e:c2f2:bc5f:e9c6%11"),
        ip_address("fdc8:d776:7cca:46ed::2"),
    ]
    assert info.parsed_scoped_addresses() == [
        "fe80::52e:c2f2:bc5f:e9c6%11",
        "fdc8:d776:7cca:46ed::2",
    ]
    zeroconf.close()


# This test uses asyncio because it needs to access the cache directly
# which is not threadsafe
@pytest.mark.asyncio
async def test_multiple_a_addresses_newest_address_first():
    """Test that info.addresses returns the newest seen address first."""
    type_ = "_http._tcp.local."
    registration_name = f"multiarec.{type_}"
    desc = {"path": "/~paulsm/"}
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    cache = aiozc.zeroconf.cache
    host = "multahost.local."
    record1 = r.DNSAddress(host, const._TYPE_A, const._CLASS_IN, 1000, b"\x7f\x00\x00\x01")
    record2 = r.DNSAddress(host, const._TYPE_A, const._CLASS_IN, 1000, b"\x7f\x00\x00\x02")
    cache.async_add_records([record1, record2])

    # New kwarg way
    info = ServiceInfo(type_, registration_name, 80, 0, 0, desc, host)
    info.load_from_cache(aiozc.zeroconf)
    assert info.addresses == [b"\x7f\x00\x00\x02", b"\x7f\x00\x00\x01"]
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_invalid_a_addresses(caplog):
    type_ = "_http._tcp.local."
    registration_name = f"multiarec.{type_}"
    desc = {"path": "/~paulsm/"}
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    cache = aiozc.zeroconf.cache
    host = "multahost.local."
    record1 = r.DNSAddress(host, const._TYPE_A, const._CLASS_IN, 1000, b"a")
    record2 = r.DNSAddress(host, const._TYPE_A, const._CLASS_IN, 1000, b"b")
    cache.async_add_records([record1, record2])

    # New kwarg way
    info = ServiceInfo(type_, registration_name, 80, 0, 0, desc, host)
    info.load_from_cache(aiozc.zeroconf)
    assert not info.addresses
    assert "Encountered invalid address while processing record" in caplog.text

    await aiozc.async_close()


@unittest.skipIf(not has_working_ipv6(), "Requires IPv6")
@unittest.skipIf(os.environ.get("SKIP_IPV6"), "IPv6 tests disabled")
def test_filter_address_by_type_from_service_info():
    """Verify dns_addresses can filter by ipversion."""
    desc = {"path": "/~paulsm/"}
    type_ = "_homeassistant._tcp.local."
    name = "MyTestHome"
    registration_name = f"{name}.{type_}"
    ipv4 = socket.inet_aton("10.0.1.2")
    ipv6 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    info = ServiceInfo(type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[ipv4, ipv6])

    def dns_addresses_to_addresses(dns_address: list[DNSAddress]) -> list[bytes]:
        return [address.address for address in dns_address]

    assert dns_addresses_to_addresses(info.dns_addresses()) == [ipv4, ipv6]
    assert dns_addresses_to_addresses(info.dns_addresses(version=r.IPVersion.All)) == [
        ipv4,
        ipv6,
    ]
    assert dns_addresses_to_addresses(info.dns_addresses(version=r.IPVersion.V4Only)) == [ipv4]
    assert dns_addresses_to_addresses(info.dns_addresses(version=r.IPVersion.V6Only)) == [ipv6]


def test_changing_name_updates_serviceinfo_key():
    """Verify a name change will adjust the underlying key value."""
    type_ = "_homeassistant._tcp.local."
    name = "MyTestHome"
    info_service = ServiceInfo(
        type_,
        f"{name}.{type_}",
        80,
        0,
        0,
        {"path": "/~paulsm/"},
        "ash-2.local.",
        addresses=[socket.inet_aton("10.0.1.2")],
    )
    assert info_service.key == "mytesthome._homeassistant._tcp.local."
    info_service.name = "YourTestHome._homeassistant._tcp.local."
    assert info_service.key == "yourtesthome._homeassistant._tcp.local."


def test_serviceinfo_address_updates():
    """Verify adding/removing/setting addresses on ServiceInfo."""
    type_ = "_homeassistant._tcp.local."
    name = "MyTestHome"

    # Verify addresses and parsed_addresses are mutually exclusive
    with pytest.raises(TypeError):
        info_service = ServiceInfo(
            type_,
            f"{name}.{type_}",
            80,
            0,
            0,
            {"path": "/~paulsm/"},
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
            parsed_addresses=["10.0.1.2"],
        )

    info_service = ServiceInfo(
        type_,
        f"{name}.{type_}",
        80,
        0,
        0,
        {"path": "/~paulsm/"},
        "ash-2.local.",
        addresses=[socket.inet_aton("10.0.1.2")],
    )
    info_service.addresses = [socket.inet_aton("10.0.1.3")]
    assert info_service.addresses == [socket.inet_aton("10.0.1.3")]


def test_serviceinfo_accepts_bytes_or_string_dict():
    """Verify a bytes or string dict can be passed to ServiceInfo."""
    type_ = "_homeassistant._tcp.local."
    name = "MyTestHome"
    addresses = [socket.inet_aton("10.0.1.2")]
    server_name = "ash-2.local."
    info_service = ServiceInfo(
        type_,
        f"{name}.{type_}",
        80,
        0,
        0,
        {b"path": b"/~paulsm/"},
        server_name,
        addresses=addresses,
    )
    assert info_service.dns_text().text == b"\x0epath=/~paulsm/"
    info_service = ServiceInfo(
        type_,
        f"{name}.{type_}",
        80,
        0,
        0,
        {"path": "/~paulsm/"},
        server_name,
        addresses=addresses,
    )
    assert info_service.dns_text().text == b"\x0epath=/~paulsm/"
    info_service = ServiceInfo(
        type_,
        f"{name}.{type_}",
        80,
        0,
        0,
        {b"path": "/~paulsm/"},
        server_name,
        addresses=addresses,
    )
    assert info_service.dns_text().text == b"\x0epath=/~paulsm/"
    info_service = ServiceInfo(
        type_,
        f"{name}.{type_}",
        80,
        0,
        0,
        {"path": b"/~paulsm/"},
        server_name,
        addresses=addresses,
    )
    assert info_service.dns_text().text == b"\x0epath=/~paulsm/"


def test_asking_qu_questions(quick_request_timing):
    """Verify explicitly asking QU questions."""
    type_ = "_quservice._tcp.local."
    zeroconf = r.Zeroconf(interfaces=["127.0.0.1"])

    # we are going to patch the zeroconf send to check query transmission
    old_send = zeroconf.async_send

    first_outgoing = None

    def send(out, addr=const._MDNS_ADDR, port=const._MDNS_PORT):
        nonlocal first_outgoing
        if first_outgoing is None:
            first_outgoing = out
        old_send(out, addr=addr, port=port)

    # patch the zeroconf send
    with patch.object(zeroconf, "async_send", send):
        zeroconf.get_service_info(
            f"name.{type_}", type_, QUICK_REQUEST_TIMEOUT_MS, question_type=r.DNSQuestionType.QU
        )
        assert first_outgoing.questions[0].unicast is True  # type: ignore[union-attr]
        zeroconf.close()


def test_asking_qm_questions(quick_request_timing):
    """Verify explicitly asking QM questions."""
    type_ = "_quservice._tcp.local."
    zeroconf = r.Zeroconf(interfaces=["127.0.0.1"])

    # we are going to patch the zeroconf send to check query transmission
    old_send = zeroconf.async_send

    first_outgoing = None

    def send(out, addr=const._MDNS_ADDR, port=const._MDNS_PORT):
        nonlocal first_outgoing
        if first_outgoing is None:
            first_outgoing = out
        old_send(out, addr=addr, port=port)

    # patch the zeroconf send
    with patch.object(zeroconf, "async_send", send):
        zeroconf.get_service_info(
            f"name.{type_}", type_, QUICK_REQUEST_TIMEOUT_MS, question_type=r.DNSQuestionType.QM
        )
        assert first_outgoing.questions[0].unicast is False  # type: ignore[union-attr]
        zeroconf.close()


def test_request_timeout():
    """Test that the timeout does not throw an exception and finishes close to the actual timeout."""
    zeroconf = r.Zeroconf(interfaces=["127.0.0.1"])
    start_time = r.current_time_millis()
    assert zeroconf.get_service_info("_notfound.local.", "notthere._notfound.local.", timeout=200) is None
    end_time = r.current_time_millis()
    zeroconf.close()
    # 200ms for the timeout passed above
    # 1000ms for loaded systems + schedule overhead
    assert (end_time - start_time) < 200 + 1000


@pytest.mark.asyncio
async def test_we_try_four_times_with_random_delay():
    """Verify we try four times even with the random delay."""
    type_ = "_typethatisnothere._tcp.local."
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])

    # we are going to patch the zeroconf send to check query transmission
    request_count = 0

    def async_send(out, addr=const._MDNS_ADDR, port=const._MDNS_PORT):
        nonlocal request_count
        request_count += 1

    # patch the zeroconf send
    with patch.object(aiozc.zeroconf, "async_send", async_send):
        await aiozc.async_get_service_info(f"willnotbefound.{type_}", type_)

    await aiozc.async_close()

    assert request_count == 4


@pytest.mark.asyncio
async def test_release_wait_when_new_recorded_added():
    """Test that async_request returns as soon as new matching records are added to the cache."""
    type_ = "_http._tcp.local."
    registration_name = f"multiarec.{type_}"
    desc = {"path": "/~paulsm/"}
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    host = "multahost.local."

    # New kwarg way
    info = ServiceInfo(type_, registration_name, 80, 0, 0, desc, host)
    task = asyncio.create_task(info.async_request(aiozc.zeroconf, timeout=200))
    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSNsec(
            registration_name,
            const._TYPE_NSEC,
            const._CLASS_IN | const._CLASS_UNIQUE,
            const._DNS_OTHER_TTL,
            registration_name,
            [const._TYPE_AAAA],
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSService(
            registration_name,
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            0,
            0,
            80,
            host,
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSAddress(
            host,
            const._TYPE_A,
            const._CLASS_IN,
            10000,
            b"\x7f\x00\x00\x01",
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSText(
            registration_name,
            const._TYPE_TXT,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            b"\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==",
        ),
        0,
    )
    await aiozc.zeroconf.async_wait_for_start()
    await asyncio.sleep(0)
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))
    assert await asyncio.wait_for(task, timeout=2)
    assert info.addresses == [b"\x7f\x00\x00\x01"]
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_port_changes_are_seen():
    """Test that port changes are seen by async_request."""
    type_ = "_http._tcp.local."
    registration_name = f"multiarec.{type_}"
    desc = {"path": "/~paulsm/"}
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    host = "multahost.local."

    # New kwarg way
    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSNsec(
            registration_name,
            const._TYPE_NSEC,
            const._CLASS_IN | const._CLASS_UNIQUE,
            const._DNS_OTHER_TTL,
            registration_name,
            [const._TYPE_AAAA],
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSService(
            registration_name,
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            0,
            0,
            80,
            host,
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSAddress(
            host,
            const._TYPE_A,
            const._CLASS_IN,
            10000,
            b"\x7f\x00\x00\x01",
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSText(
            registration_name,
            const._TYPE_TXT,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            b"\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==",
        ),
        0,
    )
    await aiozc.zeroconf.async_wait_for_start()
    await asyncio.sleep(0)
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))

    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSService(
            registration_name,
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            90,
            90,
            81,
            host,
        ),
        0,
    )
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))

    info = ServiceInfo(type_, registration_name, 80, 10, 10, desc, host)
    await info.async_request(aiozc.zeroconf, timeout=200)
    assert info.port == 81
    assert info.priority == 90
    assert info.weight == 90
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_port_changes_are_seen_with_directed_request():
    """Test that port changes are seen by async_request with a directed request."""
    type_ = "_http._tcp.local."
    registration_name = f"multiarec.{type_}"
    desc = {"path": "/~paulsm/"}
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    host = "multahost.local."

    # New kwarg way
    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSNsec(
            registration_name,
            const._TYPE_NSEC,
            const._CLASS_IN | const._CLASS_UNIQUE,
            const._DNS_OTHER_TTL,
            registration_name,
            [const._TYPE_AAAA],
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSService(
            registration_name,
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            0,
            0,
            80,
            host,
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSAddress(
            host,
            const._TYPE_A,
            const._CLASS_IN,
            10000,
            b"\x7f\x00\x00\x01",
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSText(
            registration_name,
            const._TYPE_TXT,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            b"\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==",
        ),
        0,
    )
    await aiozc.zeroconf.async_wait_for_start()
    await asyncio.sleep(0)
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))

    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSService(
            registration_name,
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            90,
            90,
            81,
            host,
        ),
        0,
    )
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))

    info = ServiceInfo(type_, registration_name, 80, 10, 10, desc, host)
    await info.async_request(aiozc.zeroconf, timeout=200, addr="127.0.0.1", port=5353)
    assert info.port == 81
    assert info.priority == 90
    assert info.weight == 90
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_ipv4_changes_are_seen():
    """Test that ipv4 changes are seen by async_request."""
    type_ = "_http._tcp.local."
    registration_name = f"multiaipv4rec.{type_}"
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    host = "multahost.local."

    # New kwarg way
    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSNsec(
            registration_name,
            const._TYPE_NSEC,
            const._CLASS_IN | const._CLASS_UNIQUE,
            const._DNS_OTHER_TTL,
            registration_name,
            [const._TYPE_AAAA],
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSService(
            registration_name,
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            0,
            0,
            80,
            host,
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSAddress(
            host,
            const._TYPE_A,
            const._CLASS_IN,
            10000,
            b"\x7f\x00\x00\x01",
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSText(
            registration_name,
            const._TYPE_TXT,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            b"\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==",
        ),
        0,
    )
    await aiozc.zeroconf.async_wait_for_start()
    await asyncio.sleep(0)
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))
    info = ServiceInfo(type_, registration_name)
    info.load_from_cache(aiozc.zeroconf)
    assert info.addresses_by_version(IPVersion.V4Only) == [b"\x7f\x00\x00\x01"]

    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSAddress(
            host,
            const._TYPE_A,
            const._CLASS_IN,
            10000,
            b"\x7f\x00\x00\x02",
        ),
        0,
    )
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))

    info = ServiceInfo(type_, registration_name)
    info.load_from_cache(aiozc.zeroconf)
    assert info.addresses_by_version(IPVersion.V4Only) == [
        b"\x7f\x00\x00\x02",
        b"\x7f\x00\x00\x01",
    ]
    await info.async_request(aiozc.zeroconf, timeout=200)
    assert info.addresses_by_version(IPVersion.V4Only) == [
        b"\x7f\x00\x00\x02",
        b"\x7f\x00\x00\x01",
    ]
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_ipv6_changes_are_seen():
    """Test that ipv6 changes are seen by async_request."""
    type_ = "_http._tcp.local."
    registration_name = f"multiaipv6rec.{type_}"
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    host = "multahost.local."

    # New kwarg way
    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSNsec(
            registration_name,
            const._TYPE_NSEC,
            const._CLASS_IN | const._CLASS_UNIQUE,
            const._DNS_OTHER_TTL,
            registration_name,
            [const._TYPE_A],
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSService(
            registration_name,
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            0,
            0,
            80,
            host,
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSAddress(
            host,
            const._TYPE_AAAA,
            const._CLASS_IN,
            10000,
            b"\xde\xad\xbe\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSText(
            registration_name,
            const._TYPE_TXT,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            b"\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==",
        ),
        0,
    )
    await aiozc.zeroconf.async_wait_for_start()
    await asyncio.sleep(0)
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))
    info = ServiceInfo(type_, registration_name)
    info.load_from_cache(aiozc.zeroconf)
    assert info.addresses_by_version(IPVersion.V6Only) == [
        b"\xde\xad\xbe\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ]
    info.load_from_cache(aiozc.zeroconf)
    assert info.addresses_by_version(IPVersion.V6Only) == [
        b"\xde\xad\xbe\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00"
    ]

    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSAddress(
            host,
            const._TYPE_AAAA,
            const._CLASS_IN,
            10000,
            b"\x00\xad\xbe\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        ),
        0,
    )
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))

    info = ServiceInfo(type_, registration_name)
    info.load_from_cache(aiozc.zeroconf)
    assert info.addresses_by_version(IPVersion.V6Only) == [
        b"\x00\xad\xbe\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\xde\xad\xbe\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ]
    await info.async_request(aiozc.zeroconf, timeout=200)
    assert info.addresses_by_version(IPVersion.V6Only) == [
        b"\x00\xad\xbe\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
        b"\xde\xad\xbe\xef\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00",
    ]

    await aiozc.async_close()


@pytest.mark.asyncio
async def test_bad_ip_addresses_ignored_in_cache():
    """Test that bad ip address in the cache are ignored async_request."""
    type_ = "_http._tcp.local."
    registration_name = f"multiarec.{type_}"
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    host = "multahost.local."

    # New kwarg way
    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSService(
            registration_name,
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            0,
            0,
            80,
            host,
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSAddress(
            host,
            const._TYPE_A,
            const._CLASS_IN,
            10000,
            b"\x7f\x00\x00\x01",
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSText(
            registration_name,
            const._TYPE_TXT,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            b"\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==",
        ),
        0,
    )
    # Manually add a bad record to the cache
    aiozc.zeroconf.cache.async_add_records([DNSAddress(host, const._TYPE_A, const._CLASS_IN, 10000, b"\x00")])

    await aiozc.zeroconf.async_wait_for_start()
    await asyncio.sleep(0)
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))
    info = ServiceInfo(type_, registration_name)
    info.load_from_cache(aiozc.zeroconf)
    assert info.addresses_by_version(IPVersion.V4Only) == [b"\x7f\x00\x00\x01"]
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_service_name_change_as_seen_has_ip_in_cache():
    """Test that service name changes are seen by async_request when the ip is in the cache."""
    type_ = "_http._tcp.local."
    registration_name = f"multiarec.{type_}"
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    host = "multahost.local."

    # New kwarg way
    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSNsec(
            registration_name,
            const._TYPE_NSEC,
            const._CLASS_IN | const._CLASS_UNIQUE,
            const._DNS_OTHER_TTL,
            registration_name,
            [const._TYPE_AAAA],
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSAddress(
            registration_name,
            const._TYPE_A,
            const._CLASS_IN,
            10000,
            b"\x7f\x00\x00\x01",
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSAddress(
            host,
            const._TYPE_A,
            const._CLASS_IN,
            10000,
            b"\x7f\x00\x00\x02",
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSText(
            registration_name,
            const._TYPE_TXT,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            b"\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==",
        ),
        0,
    )
    await aiozc.zeroconf.async_wait_for_start()
    await asyncio.sleep(0)
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))

    info = ServiceInfo(type_, registration_name)
    await info.async_request(aiozc.zeroconf, timeout=200)
    assert info.addresses_by_version(IPVersion.V4Only) == []

    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSService(
            registration_name,
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            0,
            0,
            80,
            host,
        ),
        0,
    )
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))

    info = ServiceInfo(type_, registration_name)
    await info.async_request(aiozc.zeroconf, timeout=200)
    assert info.addresses_by_version(IPVersion.V4Only) == [b"\x7f\x00\x00\x02"]

    await aiozc.async_close()


@pytest.mark.asyncio
async def test_service_name_change_as_seen_ip_not_in_cache():
    """Test that service name changes are seen by async_request when the ip is not in the cache."""
    type_ = "_http._tcp.local."
    registration_name = f"multiarec.{type_}"
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    host = "multahost.local."

    # New kwarg way
    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSNsec(
            registration_name,
            const._TYPE_NSEC,
            const._CLASS_IN | const._CLASS_UNIQUE,
            const._DNS_OTHER_TTL,
            registration_name,
            [const._TYPE_AAAA],
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSAddress(
            registration_name,
            const._TYPE_A,
            const._CLASS_IN,
            10000,
            b"\x7f\x00\x00\x01",
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSText(
            registration_name,
            const._TYPE_TXT,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            b"\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==",
        ),
        0,
    )
    await aiozc.zeroconf.async_wait_for_start()
    await asyncio.sleep(0)
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))

    info = ServiceInfo(type_, registration_name)
    await info.async_request(aiozc.zeroconf, timeout=200)
    assert info.addresses_by_version(IPVersion.V4Only) == []

    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSService(
            registration_name,
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            0,
            0,
            80,
            host,
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSAddress(
            host,
            const._TYPE_A,
            const._CLASS_IN,
            10000,
            b"\x7f\x00\x00\x02",
        ),
        0,
    )
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))

    info = ServiceInfo(type_, registration_name)
    await info.async_request(aiozc.zeroconf, timeout=200)
    assert info.addresses_by_version(IPVersion.V4Only) == [b"\x7f\x00\x00\x02"]

    await aiozc.async_close()


@pytest.mark.asyncio
@patch.object(info, "_LISTENER_TIME", 10000000)
async def test_release_wait_when_new_recorded_added_concurrency():
    """Test that concurrent async_request returns as soon as new matching records are added to the cache."""
    type_ = "_http._tcp.local."
    registration_name = f"multiareccon.{type_}"
    desc = {"path": "/~paulsm/"}
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    host = "multahostcon.local."
    await aiozc.zeroconf.async_wait_for_start()

    # New kwarg way
    info = ServiceInfo(type_, registration_name, 80, 0, 0, desc, host)
    tasks = [asyncio.create_task(info.async_request(aiozc.zeroconf, timeout=200000)) for _ in range(10)]
    await asyncio.sleep(0.1)
    for task in tasks:
        assert not task.done()
    generated = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    generated.add_answer_at_time(
        r.DNSNsec(
            registration_name,
            const._TYPE_NSEC,
            const._CLASS_IN | const._CLASS_UNIQUE,
            const._DNS_OTHER_TTL,
            registration_name,
            [const._TYPE_AAAA],
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSService(
            registration_name,
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            0,
            0,
            80,
            host,
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSAddress(
            host,
            const._TYPE_A,
            const._CLASS_IN,
            10000,
            b"\x7f\x00\x00\x01",
        ),
        0,
    )
    generated.add_answer_at_time(
        r.DNSText(
            registration_name,
            const._TYPE_TXT,
            const._CLASS_IN | const._CLASS_UNIQUE,
            10000,
            b"\x04ff=0\x04ci=2\x04sf=0\x0bsh=6fLM5A==",
        ),
        0,
    )
    await asyncio.sleep(0)
    for task in tasks:
        assert not task.done()
    aiozc.zeroconf.record_manager.async_updates_from_response(r.DNSIncoming(generated.packets()[0]))
    _, pending = await asyncio.wait(tasks, timeout=2)
    assert not pending
    assert info.addresses == [b"\x7f\x00\x00\x01"]
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_service_info_address_nsec_records() -> None:
    """Test we can generate address nsec records from ServiceInfo."""
    type_ = "_http._tcp.local."
    registration_name = f"multiareccon.{type_}"
    desc = {"path": "/~paulsm/"}
    host = "multahostcon.local."
    info = ServiceInfo(type_, registration_name, 80, 0, 0, desc, host, addresses=[b"\x7f\x00\x00\x01"])
    nsec_record = info.dns_address_nsec(50)
    assert nsec_record is not None
    assert nsec_record.name == host
    assert nsec_record.next_name == host
    assert nsec_record.type == const._TYPE_NSEC
    assert nsec_record.ttl == 50
    assert nsec_record.rdtypes == [const._TYPE_A]

    # the no-override call is memoized; mutating addresses must drop the cache
    assert info.dns_address_nsec() is not None
    assert info.dns_address_nsec() is info.dns_address_nsec()
    info.addresses = []
    assert info.dns_address_nsec() is None

    v6 = socket.inet_pton(socket.AF_INET6, "2001:db8::1")
    info.addresses = [b"\x7f\x00\x00\x01", v6]
    assert info.dns_address_nsec() is None


def test_service_info_dns_nsec_deprecated() -> None:
    """dns_nsec warns and delegates to dns_address_nsec, ignoring missing_types."""
    type_ = "_http._tcp.local."
    registration_name = f"depnsec.{type_}"
    host = "depnsec-host.local."
    info = ServiceInfo(
        type_, registration_name, 80, 0, 0, {"path": "/~paulsm/"}, host, addresses=[b"\x7f\x00\x00\x01"]
    )
    with pytest.warns(DeprecationWarning, match="dns_address_nsec"):
        record = info.dns_nsec([const._TYPE_AAAA], 50)
    assert record == info.dns_address_nsec(50)
    assert record is not None
    assert record.rdtypes == [const._TYPE_A]


@pytest.mark.asyncio
async def test_address_resolver():
    """Test that the address resolver works."""
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    await aiozc.zeroconf.async_wait_for_start()
    resolver = r.AddressResolver("address_resolver_test.local.")
    resolve_task = asyncio.create_task(resolver.async_request(aiozc.zeroconf, 3000))
    outgoing = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    outgoing.add_answer_at_time(
        r.DNSAddress(
            "address_resolver_test.local.",
            const._TYPE_A,
            const._CLASS_IN,
            10000,
            b"\x7f\x00\x00\x01",
        ),
        0,
    )

    aiozc.zeroconf.async_send(outgoing)
    assert await resolve_task
    assert resolver.addresses == [b"\x7f\x00\x00\x01"]
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_address_resolver_ipv4():
    """Test that the IPv4 address resolver works."""
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    await aiozc.zeroconf.async_wait_for_start()
    resolver = r.AddressResolverIPv4("address_resolver_test_ipv4.local.")
    resolve_task = asyncio.create_task(resolver.async_request(aiozc.zeroconf, 3000))
    outgoing = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    outgoing.add_answer_at_time(
        r.DNSAddress(
            "address_resolver_test_ipv4.local.",
            const._TYPE_A,
            const._CLASS_IN,
            10000,
            b"\x7f\x00\x00\x01",
        ),
        0,
    )

    aiozc.zeroconf.async_send(outgoing)
    assert await resolve_task
    assert resolver.addresses == [b"\x7f\x00\x00\x01"]
    await aiozc.async_close()


@pytest.mark.asyncio
@unittest.skipIf(not has_working_ipv6(), "Requires IPv6")
@unittest.skipIf(os.environ.get("SKIP_IPV6"), "IPv6 tests disabled")
async def test_address_resolver_ipv6():
    """Test that the IPv6 address resolver works."""
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    await aiozc.zeroconf.async_wait_for_start()
    resolver = r.AddressResolverIPv6("address_resolver_test_ipv6.local.")
    resolve_task = asyncio.create_task(resolver.async_request(aiozc.zeroconf, 3000))
    outgoing = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    outgoing.add_answer_at_time(
        r.DNSAddress(
            "address_resolver_test_ipv6.local.",
            const._TYPE_AAAA,
            const._CLASS_IN,
            10000,
            socket.inet_pton(socket.AF_INET6, "fe80::52e:c2f2:bc5f:e9c6"),
        ),
        0,
    )

    aiozc.zeroconf.async_send(outgoing)
    assert await resolve_task
    assert resolver.ip_addresses_by_version(IPVersion.All) == [ip_address("fe80::52e:c2f2:bc5f:e9c6")]
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_unicast_flag_if_requested() -> None:
    """Verify we try four times even with the random delay."""
    type_ = "_typethatisnothere._tcp.local."
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])

    def async_send(out: DNSOutgoing, addr: str | None = None, port: int = const._MDNS_PORT) -> None:
        for question in out.questions:
            assert question.unicast

    # patch the zeroconf send
    with patch.object(aiozc.zeroconf, "async_send", async_send):
        await aiozc.async_get_service_info(
            f"willnotbefound.{type_}", type_, timeout=200, question_type=r.DNSQuestionType.QU
        )

    await aiozc.async_close()


def test_load_from_cache_incomplete_without_txt_record():
    """A service with addresses but no TXT record is not complete (RFC 6763 section 6)."""
    type_ = "_http._tcp.local."
    registration_name = f"notxt.{type_}"
    host = "notxt.local."
    zc = r.Zeroconf(interfaces=["127.0.0.1"])
    zc.cache.async_add_records(
        [
            r.DNSService(
                registration_name,
                const._TYPE_SRV,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                0,
                0,
                80,
                host,
            ),
            r.DNSAddress(
                host,
                const._TYPE_A,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                socket.inet_aton("127.0.0.1"),
            ),
        ]
    )

    info = ServiceInfo(type_, registration_name)
    assert info.load_from_cache(zc) is False
    assert info.addresses == [socket.inet_aton("127.0.0.1")]
    zc.close()


def test_load_from_cache_complete_with_empty_txt_record():
    """An empty TXT record still completes the service; only a missing one does not."""
    type_ = "_http._tcp.local."
    registration_name = f"emptytxt.{type_}"
    host = "emptytxt.local."
    zc = r.Zeroconf(interfaces=["127.0.0.1"])
    zc.cache.async_add_records(
        [
            r.DNSService(
                registration_name,
                const._TYPE_SRV,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                0,
                0,
                80,
                host,
            ),
            r.DNSText(
                registration_name,
                const._TYPE_TXT,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                b"",
            ),
            r.DNSAddress(
                host,
                const._TYPE_A,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                socket.inet_aton("127.0.0.1"),
            ),
        ]
    )

    info = ServiceInfo(type_, registration_name)
    assert info.load_from_cache(zc) is True
    assert info.properties == {}
    zc.close()


def test_load_from_cache_complete_with_locally_set_properties():
    """Properties supplied by the caller count as the TXT data for completeness."""
    type_ = "_http._tcp.local."
    registration_name = f"localtxt.{type_}"
    host = "localtxt.local."
    zc = r.Zeroconf(interfaces=["127.0.0.1"])
    zc.cache.async_add_records(
        [
            r.DNSAddress(
                host,
                const._TYPE_A,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                socket.inet_aton("127.0.0.1"),
            ),
        ]
    )

    info = ServiceInfo(type_, registration_name, 80, 0, 0, {"path": "/~paulsm/"}, host)
    assert info.load_from_cache(zc) is True
    zc.close()


def test_load_from_cache_complete_with_empty_locally_set_properties():
    """An explicitly supplied empty properties dict counts as the TXT data."""
    type_ = "_http._tcp.local."
    registration_name = f"emptylocaltxt.{type_}"
    host = "emptylocaltxt.local."
    zc = r.Zeroconf(interfaces=["127.0.0.1"])
    zc.cache.async_add_records(
        [
            r.DNSAddress(
                host,
                const._TYPE_A,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                socket.inet_aton("127.0.0.1"),
            ),
        ]
    )

    info = ServiceInfo(type_, registration_name, 80, 0, 0, {}, host)
    assert info.load_from_cache(zc) is True
    assert info.properties == {}
    zc.close()


def test_load_from_cache_complete_with_empty_locally_set_text():
    """An explicitly supplied empty text blob counts as the TXT data."""
    type_ = "_http._tcp.local."
    registration_name = f"emptylocaltext.{type_}"
    host = "emptylocaltext.local."
    zc = r.Zeroconf(interfaces=["127.0.0.1"])
    zc.cache.async_add_records(
        [
            r.DNSAddress(
                host,
                const._TYPE_A,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                socket.inet_aton("127.0.0.1"),
            ),
        ]
    )

    info = ServiceInfo(type_, registration_name, 80, 0, 0, b"", host)
    assert info.load_from_cache(zc) is True
    assert info.properties == {}
    zc.close()


@pytest.mark.asyncio
async def test_async_request_incomplete_without_txt_record(quick_request_timing):
    """async_request fails while the responder sends no TXT record, and succeeds once it does."""
    type_ = "_http._tcp.local."
    registration_name = f"notxtrequest.{type_}"
    host = "notxtrequest.local."
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    await aiozc.zeroconf.async_wait_for_start()
    zc = aiozc.zeroconf

    address_records = [
        r.DNSService(
            registration_name,
            const._TYPE_SRV,
            const._CLASS_IN | const._CLASS_UNIQUE,
            120,
            0,
            0,
            80,
            host,
        ),
        r.DNSAddress(
            host,
            const._TYPE_A,
            const._CLASS_IN | const._CLASS_UNIQUE,
            120,
            socket.inet_aton("127.0.0.1"),
        ),
    ]
    zc.record_manager.async_updates_from_response(mock_incoming_msg(address_records))

    info = ServiceInfo(type_, registration_name)
    with patch.object(zc, "async_send"):
        assert await info.async_request(zc, QUICK_REQUEST_TIMEOUT_MS) is False

    zc.record_manager.async_updates_from_response(
        mock_incoming_msg(
            [
                r.DNSText(
                    registration_name,
                    const._TYPE_TXT,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    b"\x05ttl=2",
                )
            ]
        )
    )
    with patch.object(zc, "async_send"):
        assert await info.async_request(zc, QUICK_REQUEST_TIMEOUT_MS) is True
    assert info.properties == {b"ttl": b"2"}

    await aiozc.async_close()


@pytest.mark.parametrize(
    ("nsec_rdtypes", "expected_complete"),
    [
        # SRV bit set with TXT absent is a TXT denial (RFC 6762 §6.1)
        ([const._TYPE_SRV], True),
        # no SRV bit: the inverted bitmap older releases emitted, not a denial
        ([const._TYPE_AAAA], False),
    ],
)
def test_load_from_cache_with_nsec(
    zc_loopback: r.Zeroconf, nsec_rdtypes: list[int], expected_complete: bool
) -> None:
    """An NSEC listing SRV but not TXT denies the TXT record and completes the service."""
    type_ = "_http._tcp.local."
    registration_name = f"nsecdenial.{type_}"
    host = "nsecdenial.local."
    zc = zc_loopback
    zc.cache.async_add_records(
        [
            r.DNSService(
                registration_name,
                const._TYPE_SRV,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                0,
                0,
                80,
                host,
            ),
            r.DNSNsec(
                registration_name,
                const._TYPE_NSEC,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                registration_name,
                nsec_rdtypes,
            ),
            r.DNSAddress(
                host,
                const._TYPE_A,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                socket.inet_aton("127.0.0.1"),
            ),
        ]
    )

    info = ServiceInfo(type_, registration_name)
    assert info.load_from_cache(zc) is expected_complete
    if expected_complete:
        assert info.properties == {}


@pytest.mark.asyncio
@pytest.mark.usefixtures("quick_request_timing")
async def test_async_request_completes_on_nsec_txt_denial(aiozc_loopback: AsyncZeroconf) -> None:
    """async_request succeeds promptly when the responder denies the TXT record via NSEC."""
    type_ = "_http._tcp.local."
    registration_name = f"nsecrequest.{type_}"
    host = "nsecrequest.local."
    await aiozc_loopback.zeroconf.async_wait_for_start()
    zc = aiozc_loopback.zeroconf

    zc.record_manager.async_updates_from_response(
        mock_incoming_msg(
            [
                r.DNSService(
                    registration_name,
                    const._TYPE_SRV,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    0,
                    0,
                    80,
                    host,
                ),
                r.DNSAddress(
                    host,
                    const._TYPE_A,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    socket.inet_aton("127.0.0.1"),
                ),
            ]
        )
    )

    info = ServiceInfo(type_, registration_name)
    with patch.object(zc, "async_send"):
        assert await info.async_request(zc, QUICK_REQUEST_TIMEOUT_MS) is False

    zc.record_manager.async_updates_from_response(
        mock_incoming_msg(
            [
                r.DNSNsec(
                    registration_name,
                    const._TYPE_NSEC,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    registration_name,
                    [const._TYPE_SRV],
                )
            ]
        )
    )
    with patch.object(zc, "async_send"):
        assert await info.async_request(zc, QUICK_REQUEST_TIMEOUT_MS) is True
    assert info.properties == {}

    zc.record_manager.async_updates_from_response(
        mock_incoming_msg(
            [
                r.DNSText(
                    registration_name,
                    const._TYPE_TXT,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    b"\x05ttl=2",
                )
            ]
        )
    )
    assert info.load_from_cache(zc) is True
    assert info.properties == {b"ttl": b"2"}


@pytest.mark.asyncio
async def test_nsec_after_txt_record_is_ignored(aiozc_loopback: AsyncZeroconf) -> None:
    """An NSEC arriving after a real TXT record does not clear the properties."""
    type_ = "_http._tcp.local."
    registration_name = f"nsecaftertxt.{type_}"
    host = "nsecaftertxt.local."
    await aiozc_loopback.zeroconf.async_wait_for_start()
    zc = aiozc_loopback.zeroconf

    zc.record_manager.async_updates_from_response(
        mock_incoming_msg(
            [
                r.DNSService(
                    registration_name,
                    const._TYPE_SRV,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    0,
                    0,
                    80,
                    host,
                ),
                r.DNSText(
                    registration_name,
                    const._TYPE_TXT,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    b"\x05ttl=2",
                ),
                r.DNSAddress(
                    host,
                    const._TYPE_A,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    socket.inet_aton("127.0.0.1"),
                ),
            ]
        )
    )

    info = ServiceInfo(type_, registration_name)
    assert info.load_from_cache(zc) is True

    nsec_record = r.DNSNsec(
        registration_name,
        const._TYPE_NSEC,
        const._CLASS_IN | const._CLASS_UNIQUE,
        120,
        registration_name,
        [const._TYPE_SRV],
    )
    info.async_update_records(zc, r.current_time_millis(), [RecordUpdate(nsec_record, None)])
    assert info.properties == {b"ttl": b"2"}
    assert info._is_complete


def test_unhandled_record_type_at_service_name_is_ignored(zc_loopback: r.Zeroconf) -> None:
    """A record type with no handler at the service name does not change state."""
    type_ = "_http._tcp.local."
    registration_name = f"unhandledrec.{type_}"
    info = ServiceInfo(type_, registration_name)
    ptr_record = r.DNSPointer(
        registration_name,
        const._TYPE_PTR,
        const._CLASS_IN,
        120,
        f"other.{type_}",
    )
    info.async_update_records(zc_loopback, r.current_time_millis(), [RecordUpdate(ptr_record, None)])
    assert info._txt_seen is False
    assert info._is_complete is False


@pytest.mark.asyncio
async def test_own_nsec_response_does_not_complete_service(aiozc_loopback: AsyncZeroconf) -> None:
    """The NSEC our own responder emits for a missing address type must not deny the TXT record."""
    type_ = "_http._tcp.local."
    registration_name = f"ownnsec.{type_}"
    host = "ownnsec.local."
    await aiozc_loopback.zeroconf.async_wait_for_start()
    zc = aiozc_loopback.zeroconf

    registered = ServiceInfo(
        type_,
        registration_name,
        80,
        0,
        0,
        {"path": "/~paulsm/"},
        host,
        addresses=[socket.inet_aton("10.0.1.2")],
    )
    zc.record_manager.async_updates_from_response(
        mock_incoming_msg([registered.dns_service(), *registered.get_address_and_nsec_records()])
    )

    info = ServiceInfo(type_, registration_name)
    assert info.load_from_cache(zc) is False


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("resolver_class", "nsec_rdtypes"),
    [
        (r.AddressResolverIPv4, [const._TYPE_AAAA]),
        (r.AddressResolverIPv6, [const._TYPE_A]),
    ],
)
async def test_address_resolver_bails_on_nsec_denial(
    aiozc_loopback: AsyncZeroconf,
    resolver_class: Callable[[str], ServiceInfo],
    nsec_rdtypes: list[int],
) -> None:
    """A cached NSEC denying the wanted address type fails the request without waiting."""
    host = "nsec-addr-denial.local."
    await aiozc_loopback.zeroconf.async_wait_for_start()
    zc = aiozc_loopback.zeroconf

    zc.record_manager.async_updates_from_response(
        mock_incoming_msg(
            [
                r.DNSNsec(
                    host,
                    const._TYPE_NSEC,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    host,
                    nsec_rdtypes,
                )
            ]
        )
    )

    resolver = resolver_class(host)
    start = time.monotonic()
    with patch.object(zc, "async_send") as mock_send:
        assert await resolver.async_request(zc, 10000) is False
    assert time.monotonic() - start < 2
    # a cached denial fails without putting a query on the wire
    assert mock_send.call_count == 0


@pytest.mark.asyncio
async def test_address_resolver_bails_on_live_nsec_denial(aiozc_loopback: AsyncZeroconf) -> None:
    """An NSEC denial arriving mid request wakes the waiter and fails it early."""
    host = "nsec-live-denial.local."
    await aiozc_loopback.zeroconf.async_wait_for_start()
    zc = aiozc_loopback.zeroconf

    resolver = r.AddressResolverIPv6(host)
    start = time.monotonic()
    with patch.object(zc, "async_send"):
        task = asyncio.ensure_future(resolver.async_request(zc, 10000))
        await asyncio.sleep(0.1)
        assert not task.done()
        zc.record_manager.async_updates_from_response(
            mock_incoming_msg(
                [
                    r.DNSNsec(
                        host,
                        const._TYPE_NSEC,
                        const._CLASS_IN | const._CLASS_UNIQUE,
                        120,
                        host,
                        [const._TYPE_A],
                    )
                ]
            )
        )
        assert await task is False
    assert time.monotonic() - start < 2


@pytest.mark.asyncio
async def test_address_resolver_succeeds_despite_partial_denial(
    aiozc_loopback: AsyncZeroconf,
) -> None:
    """Denial of one address family does not fail a resolver that accepts either."""
    host = "nsec-partial-denial.local."
    await aiozc_loopback.zeroconf.async_wait_for_start()
    zc = aiozc_loopback.zeroconf

    zc.record_manager.async_updates_from_response(
        mock_incoming_msg(
            [
                r.DNSAddress(
                    host,
                    const._TYPE_A,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    socket.inet_aton("127.0.0.1"),
                ),
                r.DNSNsec(
                    host,
                    const._TYPE_NSEC,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    host,
                    [const._TYPE_A],
                ),
            ]
        )
    )

    resolver = r.AddressResolver(host)
    with patch.object(zc, "async_send"):
        assert await resolver.async_request(zc, QUICK_REQUEST_TIMEOUT_MS) is True
    assert resolver.addresses == [socket.inet_aton("127.0.0.1")]


@pytest.mark.asyncio
async def test_address_resolver_bails_when_other_family_is_present(
    aiozc_loopback: AsyncZeroconf,
) -> None:
    """A cached NSEC denial bails a single family resolver even when the other family resolved."""
    host = "nsec-mixed-denial.local."
    await aiozc_loopback.zeroconf.async_wait_for_start()
    zc = aiozc_loopback.zeroconf

    zc.record_manager.async_updates_from_response(
        mock_incoming_msg(
            [
                r.DNSAddress(
                    host,
                    const._TYPE_A,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    socket.inet_aton("127.0.0.1"),
                ),
                r.DNSNsec(
                    host,
                    const._TYPE_NSEC,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    host,
                    [const._TYPE_A],
                ),
            ]
        )
    )

    resolver = r.AddressResolverIPv6(host)
    start = time.monotonic()
    with patch.object(zc, "async_send"):
        assert await resolver.async_request(zc, 10000) is False
    assert time.monotonic() - start < 2


@pytest.mark.asyncio
async def test_address_denial_cleared_on_new_request(aiozc_loopback: AsyncZeroconf) -> None:
    """A denial only lasts one request; a host that gains the record resolves again."""
    host = "nsec-denial-reset.local."
    await aiozc_loopback.zeroconf.async_wait_for_start()
    zc = aiozc_loopback.zeroconf

    zc.record_manager.async_updates_from_response(
        mock_incoming_msg(
            [
                r.DNSNsec(
                    host,
                    const._TYPE_NSEC,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    host,
                    [const._TYPE_A],
                )
            ]
        )
    )

    resolver = r.AddressResolverIPv6(host)
    with patch.object(zc, "async_send"):
        assert await resolver.async_request(zc, 10000) is False

    v6 = socket.inet_pton(socket.AF_INET6, "fd00::1")
    zc.record_manager.async_updates_from_response(
        mock_incoming_msg(
            [
                r.DNSAddress(
                    host,
                    const._TYPE_AAAA,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    v6,
                )
            ]
        )
    )
    with patch.object(zc, "async_send"):
        assert await resolver.async_request(zc, QUICK_REQUEST_TIMEOUT_MS) is True
    assert resolver.ip_addresses_by_version(IPVersion.V6Only)


@pytest.mark.asyncio
async def test_service_info_bails_when_all_address_types_denied(
    aiozc_loopback: AsyncZeroconf,
) -> None:
    """An NSEC denying both address families at the host fails the request early."""
    type_ = "_http._tcp.local."
    registration_name = f"alldenied.{type_}"
    host = "alldenied-host.local."
    await aiozc_loopback.zeroconf.async_wait_for_start()
    zc = aiozc_loopback.zeroconf

    zc.record_manager.async_updates_from_response(
        mock_incoming_msg(
            [
                r.DNSService(
                    registration_name,
                    const._TYPE_SRV,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    0,
                    0,
                    80,
                    host,
                ),
                r.DNSText(
                    registration_name,
                    const._TYPE_TXT,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    b"\x05ttl=2",
                ),
                r.DNSNsec(
                    host,
                    const._TYPE_NSEC,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    host,
                    [const._TYPE_TXT],
                ),
            ]
        )
    )

    info = ServiceInfo(type_, registration_name)
    start = time.monotonic()
    with patch.object(zc, "async_send"):
        assert await info.async_request(zc, 10000) is False
    assert time.monotonic() - start < 2


def test_nsec_for_unrelated_name_is_ignored(zc_loopback: r.Zeroconf) -> None:
    """An NSEC for a name that is neither the service nor the server changes nothing."""
    type_ = "_http._tcp.local."
    registration_name = f"unrelatednsec.{type_}"
    info = ServiceInfo(type_, registration_name)
    foreign_nsec = r.DNSNsec(
        "other-host.local.",
        const._TYPE_NSEC,
        const._CLASS_IN | const._CLASS_UNIQUE,
        120,
        "other-host.local.",
        [const._TYPE_A],
    )
    info.async_update_records(zc_loopback, r.current_time_millis(), [RecordUpdate(foreign_nsec, None)])
    assert info._ipv4_denied is False
    assert info._ipv6_denied is False
    assert info._txt_seen is False


def _nsec(name: str, rdtypes: list[int]) -> r.DNSNsec:
    return r.DNSNsec(
        name,
        const._TYPE_NSEC,
        const._CLASS_IN | const._CLASS_UNIQUE,
        120,
        name,
        rdtypes,
    )


def _srv(name: str, host: str) -> r.DNSService:
    return r.DNSService(
        name,
        const._TYPE_SRV,
        const._CLASS_IN | const._CLASS_UNIQUE,
        120,
        0,
        0,
        80,
        host,
    )


@pytest.mark.parametrize("nsec_first", [False, True])
def test_nsec_and_srv_in_same_batch_record_denial(zc_loopback: r.Zeroconf, nsec_first: bool) -> None:
    """A batch with an SRV and an NSEC for its target records the denial in either order."""
    type_ = "_http._tcp.local."
    registration_name = f"nsecfirst.{type_}"
    host = "nsecfirst-host.local."
    info = ServiceInfo(type_, registration_name)
    now = r.current_time_millis()
    records = [_nsec(host, [const._TYPE_TXT]), _srv(registration_name, host)]
    if not nsec_first:
        records.reverse()
    info.async_update_records(zc_loopback, now, [RecordUpdate(record, None) for record in records])
    assert (info._ipv4_denied, info._ipv6_denied) == (True, True)


def test_denial_is_reset_when_srv_changes_server(zc_loopback: r.Zeroconf) -> None:
    """A denial learned for the old SRV target does not apply to a new target."""
    type_ = "_http._tcp.local."
    registration_name = f"srvmove.{type_}"
    old_host = "srvmove-old.local."
    new_host = "srvmove-new.local."
    denied_host = "srvmove-denied.local."
    info = ServiceInfo(type_, registration_name)
    now = r.current_time_millis()

    info.async_update_records(
        zc_loopback,
        now,
        [
            RecordUpdate(_srv(registration_name, old_host), None),
            RecordUpdate(_nsec(old_host, [const._TYPE_TXT]), None),
        ],
    )
    assert (info._ipv4_denied, info._ipv6_denied) == (True, True)

    # moving to a host with no cached NSEC clears the denial
    info.async_update_records(zc_loopback, now, [RecordUpdate(_srv(registration_name, new_host), None)])
    assert (info._ipv4_denied, info._ipv6_denied) == (False, False)

    # moving to a host with a cached NSEC re-establishes it from the cache
    zc_loopback.cache.async_add_records([_nsec(denied_host, [const._TYPE_TXT])])
    info.async_update_records(zc_loopback, now, [RecordUpdate(_srv(registration_name, denied_host), None)])
    assert (info._ipv4_denied, info._ipv6_denied) == (True, True)


def test_newer_nsec_clears_previous_denial(zc_loopback: r.Zeroconf) -> None:
    """A later NSEC whose bitmap includes a previously denied type clears that denial."""
    type_ = "_http._tcp.local."
    registration_name = f"nsecrefresh.{type_}"
    host = "nsecrefresh-host.local."
    info = ServiceInfo(type_, registration_name)
    now = r.current_time_millis()
    info.async_update_records(zc_loopback, now, [RecordUpdate(_srv(registration_name, host), None)])

    info.async_update_records(zc_loopback, now, [RecordUpdate(_nsec(host, [const._TYPE_A]), None)])
    assert (info._ipv4_denied, info._ipv6_denied) == (False, True)

    info.async_update_records(
        zc_loopback, now, [RecordUpdate(_nsec(host, [const._TYPE_A, const._TYPE_AAAA]), None)]
    )
    assert (info._ipv4_denied, info._ipv6_denied) == (False, False)


def test_multiple_nsec_records_in_one_batch(zc_loopback: r.Zeroconf) -> None:
    """A batch with more than one NSEC processes every denial it carries."""
    type_ = "_http._tcp.local."
    registration_name = f"multinsec.{type_}"
    host = "multinsec-host.local."
    info = ServiceInfo(type_, registration_name)
    now = r.current_time_millis()
    records = [
        _srv(registration_name, host),
        _nsec(registration_name, [const._TYPE_SRV]),
        _nsec(host, [const._TYPE_TXT]),
    ]
    info.async_update_records(zc_loopback, now, [RecordUpdate(record, None) for record in records])
    assert info._txt_seen is True
    assert (info._ipv4_denied, info._ipv6_denied) == (True, True)


@pytest.mark.asyncio
async def test_v4_only_host_with_nsec_still_resolves(aiozc_loopback: AsyncZeroconf) -> None:
    """The common case: a v4 only host denying AAAA via NSEC still resolves the service."""
    type_ = "_http._tcp.local."
    registration_name = f"v4onlynsec.{type_}"
    host = "v4onlynsec-host.local."
    await aiozc_loopback.zeroconf.async_wait_for_start()
    zc = aiozc_loopback.zeroconf

    zc.record_manager.async_updates_from_response(
        mock_incoming_msg(
            [
                _srv(registration_name, host),
                r.DNSText(
                    registration_name,
                    const._TYPE_TXT,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    b"\x05ttl=2",
                ),
                r.DNSAddress(
                    host,
                    const._TYPE_A,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    socket.inet_aton("127.0.0.1"),
                ),
                _nsec(host, [const._TYPE_A]),
            ]
        )
    )

    info = ServiceInfo(type_, registration_name)
    with patch.object(zc, "async_send"):
        assert await info.async_request(zc, QUICK_REQUEST_TIMEOUT_MS) is True
    assert info.properties == {b"ttl": b"2"}
    assert info.addresses == [socket.inet_aton("127.0.0.1")]


def test_legacy_inverted_nsec_at_own_name_does_not_fail_request(zc_loopback: r.Zeroconf) -> None:
    """A pre-0.150.4 inverted NSEC from a service with server == name never denies the request."""
    type_ = "_http._tcp.local."
    registration_name = f"legacyownname.{type_}"
    info = ServiceInfo(type_, registration_name)
    now = r.current_time_millis()
    # legacy v4 only responder registered without server=: NSEC at its own
    # name with the inverted bitmap listing the missing AAAA
    info.async_update_records(
        zc_loopback,
        now,
        [
            RecordUpdate(_srv(registration_name, registration_name), None),
            RecordUpdate(_nsec(registration_name, [const._TYPE_AAAA]), None),
        ],
    )
    assert (info._ipv4_denied, info._ipv6_denied) == (True, False)
    assert info._is_denied is False

    info.async_update_records(
        zc_loopback,
        now,
        [
            RecordUpdate(
                r.DNSAddress(
                    registration_name,
                    const._TYPE_A,
                    const._CLASS_IN | const._CLASS_UNIQUE,
                    120,
                    socket.inet_aton("127.0.0.1"),
                ),
                None,
            )
        ],
    )
    assert info.addresses == [socket.inet_aton("127.0.0.1")]
    assert info._is_denied is False


def test_denied_flag_is_ignored_when_address_is_held(zc_loopback: r.Zeroconf) -> None:
    """A denial never vetoes an address the client already holds."""
    type_ = "_http._tcp.local."
    registration_name = f"guardednsec.{type_}"
    host = "guardednsec-host.local."
    zc_loopback.cache.async_add_records(
        [
            _srv(registration_name, host),
            r.DNSAddress(
                host,
                const._TYPE_A,
                const._CLASS_IN | const._CLASS_UNIQUE,
                120,
                socket.inet_aton("127.0.0.1"),
            ),
            _nsec(host, [const._TYPE_TXT]),
        ]
    )

    info = ServiceInfo(type_, registration_name)
    # incomplete only because the TXT record is still missing
    assert info.load_from_cache(zc_loopback) is False
    assert (info._ipv4_denied, info._ipv6_denied) == (True, True)
    assert info.addresses == [socket.inet_aton("127.0.0.1")]
    # the held A record keeps the request querying instead of fast failing
    assert info._is_denied is False


@pytest.mark.parametrize(
    "addresses",
    [
        ["10.0.1.2", "2001:db8::1"],
        [socket.inet_aton("10.0.1.2"), socket.inet_pton(socket.AF_INET6, "2001:db8::1")],
        ["10.0.1.2", socket.inet_pton(socket.AF_INET6, "2001:db8::1")],
    ],
)
def test_addresses_setter_accepts_str_and_bytes(addresses):
    """The addresses setter accepts str and bytes addresses."""
    type_ = "_http._tcp.local."
    info = ServiceInfo(type_, f"xxxyyy.{type_}", 80, server="ash-2.local.")
    info.addresses = addresses
    assert info.parsed_addresses() == ["10.0.1.2", "2001:db8::1"]

    info = ServiceInfo(type_, f"xxxyyy.{type_}", 80, server="ash-2.local.", addresses=addresses)
    assert info.parsed_addresses() == ["10.0.1.2", "2001:db8::1"]


def test_addresses_setter_rejects_invalid_address():
    """The addresses setter raises TypeError for invalid addresses."""
    type_ = "_http._tcp.local."
    info = ServiceInfo(type_, f"xxxyyy.{type_}", 80, server="ash-2.local.")
    with pytest.raises(TypeError, match="Addresses must either be"):
        info.addresses = ["not an address"]
