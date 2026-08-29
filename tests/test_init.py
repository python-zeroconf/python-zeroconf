from __future__ import annotations

import logging
import socket
import time
from unittest.mock import patch

import pytest

import zeroconf as r
from zeroconf import ServiceInfo, Zeroconf, const

from . import _inject_responses

log = logging.getLogger("zeroconf")
original_logging_level = logging.NOTSET


def setup_module():
    global original_logging_level
    original_logging_level = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    if original_logging_level != logging.NOTSET:
        log.setLevel(original_logging_level)


@pytest.mark.parametrize("label_count", [12, 1000, 4000])
def test_names_with_many_labels_encode_without_error(label_count):
    """Encoding and re-parsing a deeply nested name never raises."""
    out = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    out.add_question(r.DNSQuestion("z." * label_count + "local.", const._TYPE_SRV, const._CLASS_IN))
    r.DNSIncoming(out.packets()[0])


def test_oversized_label_is_rejected_at_encode_time():
    """A single label above 63 bytes cannot be written (RFC 1035 section 2.3.4)."""
    out = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    out.add_question(r.DNSQuestion("q" * 70 + ".local.", const._TYPE_SRV, const._CLASS_IN))
    with pytest.raises(r.NamePartTooLongException):
        out.packets()


def test_repeating_a_question_keeps_every_copy():
    out = r.DNSOutgoing(const._FLAGS_QR_RESPONSE)
    duplicate = r.DNSQuestion("twin-entry.local.", const._TYPE_SRV, const._CLASS_IN)
    for _ in range(2):
        out.add_question(duplicate)
    assert r.DNSIncoming(out.packets()[0]).num_questions == 2


@pytest.mark.usefixtures("quick_timing")
def test_verify_name_change_with_lots_of_names():
    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=["127.0.0.1"])

    # create a bunch of servers
    type_ = "_my-service._tcp.local."
    name = "a wonderful service"
    server_count = 300
    generate_many_hosts(zc, type_, name, server_count)

    # verify that name changing works
    verify_name_change(zc, type_, name, server_count)

    zc.close()


def test_large_packet_exception_log_handling():
    """Verify we downgrade debug after warning."""

    # instantiate a zeroconf instance
    zc = Zeroconf(interfaces=["127.0.0.1"])

    with (
        patch("zeroconf._logger.log.warning") as mocked_log_warn,
        patch("zeroconf._logger.log.debug") as mocked_log_debug,
    ):
        # now that we have a long packet in our possession, let's verify the
        # exception handling.
        out = r.DNSOutgoing(const._FLAGS_QR_RESPONSE | const._FLAGS_AA)
        out.data.append(b"\0" * 10000)

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
        r.log.debug(
            "warn %d debug %d was %s",
            mocked_log_warn.call_count,
            mocked_log_debug.call_count,
            call_counts,
        )
        assert mocked_log_debug.call_count > call_counts[0]

    # close our zeroconf which will close the sockets
    zc.close()


def verify_name_change(zc, type_, name, number_hosts):
    desc = {"path": "/healthz/"}
    info_service = ServiceInfo(
        type_,
        f"{name}.{type_}",
        80,
        0,
        0,
        desc,
        "spare-rig.local.",
        addresses=[socket.inet_aton("10.7.4.2")],
    )

    # verify name conflict
    with pytest.raises(r.NonUniqueNameException):
        zc.register_service(info_service)

    # verify no name conflict https://tools.ietf.org/html/rfc6762#section-6.6
    zc.register_service(info_service, cooperating_responders=True)

    # Create a new object since allow_name_change will mutate the
    # original object and then we will have the wrong service
    # in the registry
    info_service2 = ServiceInfo(
        type_,
        f"{name}.{type_}",
        80,
        0,
        0,
        desc,
        "spare-rig.local.",
        addresses=[socket.inet_aton("10.7.4.2")],
    )
    zc.register_service(info_service2, allow_name_change=True)
    assert info_service2.name.split(".")[0] == f"{name}-{number_hosts + 1}"


def generate_many_hosts(zc, type_, name, number_hosts):
    block_size = 25
    number_hosts = int((number_hosts - 1) / block_size + 1) * block_size
    out = r.DNSOutgoing(const._FLAGS_QR_RESPONSE | const._FLAGS_AA)
    for i in range(1, number_hosts + 1):
        next_name = name if i == 1 else f"{name}-{i}"
        generate_host(out, next_name, type_)

    _inject_responses(zc, [r.DNSIncoming(packet) for packet in out.packets()])


def generate_host(out, host_name, type_):
    name = ".".join((host_name, type_))
    out.add_answer_at_time(
        r.DNSPointer(type_, const._TYPE_PTR, const._CLASS_IN, const._DNS_OTHER_TTL, name),
        0,
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
