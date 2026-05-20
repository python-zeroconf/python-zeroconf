"""conftest for zeroconf tests."""

from __future__ import annotations

import threading
from collections.abc import AsyncGenerator, Generator
from unittest.mock import patch

import pytest

from zeroconf import Zeroconf, _core, const
from zeroconf._handlers import query_handler
from zeroconf._services import browser as service_browser
from zeroconf._services import info as service_info
from zeroconf.asyncio import AsyncZeroconf


@pytest.fixture(autouse=True)
def verify_threads_ended():
    """Verify that the threads are not running after the test."""
    threads_before = frozenset(threading.enumerate())
    yield
    threads = frozenset(threading.enumerate()) - threads_before
    assert not threads


@pytest.fixture
def zc_loopback() -> Generator[Zeroconf]:
    """Yield a loopback `Zeroconf` and close it on teardown.

    Replaces the inline `zc = Zeroconf(interfaces=["127.0.0.1"])` +
    explicit `zc.close()` pattern duplicated across the suite. Calling
    `zc.close()` inside a test is still safe — `close()` is idempotent.
    """
    zc = Zeroconf(interfaces=["127.0.0.1"])
    try:
        yield zc
    finally:
        zc.close()


@pytest.fixture
async def aiozc_loopback() -> AsyncGenerator[AsyncZeroconf]:
    """Yield a loopback `AsyncZeroconf` and close it on teardown.

    Replaces the inline `aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])`
    + explicit `await aiozc.async_close()` pattern duplicated across the
    suite. Calling `async_close()` inside a test is still safe.
    """
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    try:
        yield aiozc
    finally:
        await aiozc.async_close()


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
    """Shorten the probe/announce/goodbye/first-query intervals for tests on loopback.

    The production values (_CHECK_TIME=500ms, _REGISTER_TIME=225ms,
    _UNREGISTER_TIME=125ms, _FIRST_QUERY_DELAY_RANDOM_INTERVAL=20-120ms)
    exist for RFC 6762 interop on real networks (§8.1 thundering-herd
    avoidance for probing, §5.2 for the initial-query delay). Tests on
    127.0.0.1 do not need them and pay 1-2s per register/unregister
    cycle and 20-120ms per ServiceBrowser startup without this fixture.
    Opt in by adding `quick_timing` to a test's argument list.
    """
    with (
        patch.object(_core, "_CHECK_TIME", 10),
        patch.object(_core, "_REGISTER_TIME", 10),
        patch.object(_core, "_UNREGISTER_TIME", 10),
        patch.object(service_browser, "_FIRST_QUERY_DELAY_RANDOM_INTERVAL", (1, 5)),
    ):
        yield


@pytest.fixture
def quick_request_timing() -> Generator[None]:
    """Shorten the initial-query delay used by AsyncServiceInfo.async_request.

    The 200ms `_LISTENER_TIME` and 20-120ms random jitter (RFC 6762
    §5.2) help spread queries from multiple clients on real networks.
    On loopback they're pure overhead — get_service_info-style tests
    wait ~250ms before the first query even fires. Opt in by adding
    `quick_request_timing` to a test's argument list, then drop the
    test's own timeouts (which had to accommodate that delay).
    """
    with (
        patch.object(service_info, "_LISTENER_TIME", 10),
        patch.object(service_info, "_AVOID_SYNC_DELAY_RANDOM_INTERVAL", (1, 5)),
    ):
        yield
