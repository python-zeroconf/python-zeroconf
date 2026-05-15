"""conftest for zeroconf tests."""

from __future__ import annotations

import threading
from collections.abc import Generator
from unittest.mock import patch

import pytest

from zeroconf import _core, const
from zeroconf._handlers import query_handler


@pytest.fixture(autouse=True)
def verify_threads_ended():
    """Verify that the threads are not running after the test."""
    threads_before = frozenset(threading.enumerate())
    yield
    threads = frozenset(threading.enumerate()) - threads_before
    assert not threads


@pytest.fixture
def run_isolated():
    """Change the mDNS port to run the test in isolation."""
    with (
        patch.object(query_handler, "_MDNS_PORT", 5454),
        patch.object(_core, "_MDNS_PORT", 5454),
        patch.object(const, "_MDNS_PORT", 5454),
    ):
        yield


@pytest.fixture
def disable_duplicate_packet_suppression():
    """Disable duplicate packet suppress.

    Some tests run too slowly because of the duplicate
    packet suppression.
    """
    with patch.object(const, "_DUPLICATE_PACKET_SUPPRESSION_INTERVAL", 0):
        yield


@pytest.fixture
def quick_timing() -> Generator[None]:
    """Shorten the probe/announce/goodbye intervals for tests on loopback.

    The production values (_CHECK_TIME=500ms, _REGISTER_TIME=225ms,
    _UNREGISTER_TIME=125ms) exist for RFC 6762 interop on real
    networks. Tests on 127.0.0.1 do not need them and pay 1-2s per
    register/unregister cycle without this fixture. Opt in by adding
    `quick_timing` to a test's argument list.
    """
    with (
        patch.object(_core, "_CHECK_TIME", 10),
        patch.object(_core, "_REGISTER_TIME", 10),
        patch.object(_core, "_UNREGISTER_TIME", 10),
    ):
        yield
