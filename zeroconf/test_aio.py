#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for async.py."""

import asyncio
import socket

import pytest

from . import REGISTER_TIME, ServiceInfo, ServiceListener, UNREGISTER_TIME, Zeroconf
from .aio import AsyncZeroconf


@pytest.mark.asyncio
async def test_async_basic_usage() -> None:
    """Test we can create and close the instance."""
    zc = AsyncZeroconf(interfaces=['127.0.0.1'])
    await zc.async_close()


@pytest.mark.asyncio
async def test_async_service_registration() -> None:
    """Test registering services broadcasts the registration by default."""
    zc = AsyncZeroconf(interfaces=['127.0.0.1'])
    type_ = "_test-srvc-type._tcp.local."
    name = "xxxyyy"
    registration_name = "%s.%s" % (name, type_)

    calls = []

    class MyListener(ServiceListener):
        def add_service(self, zeroconf: Zeroconf, type: str, name: str) -> None:
            calls.append(("add", type, name))

        def remove_service(self, zeroconf: Zeroconf, type: str, name: str) -> None:
            calls.append(("remove", type, name))

        def update_service(self, zeroconf: Zeroconf, type: str, name: str) -> None:
            calls.append(("update", type, name))

    listener = MyListener()
    zc.add_service_listener(type_, listener)

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
    await zc.async_register_service(info)
    await asyncio.sleep(REGISTER_TIME / 1000 * 3)
    new_info = ServiceInfo(
        type_,
        registration_name,
        80,
        0,
        0,
        desc,
        "ash-2.local.",
        addresses=[socket.inet_aton("10.0.1.3")],
    )
    await zc.async_update_service(new_info)
    await asyncio.sleep(REGISTER_TIME / 1000 * 3)

    await zc.async_unregister_service(new_info)
    await asyncio.sleep(UNREGISTER_TIME / 1000 * 3)
    await zc.async_close()

    assert calls == [
        ('add', '_test-srvc-type._tcp.local.', 'xxxyyy._test-srvc-type._tcp.local.'),
        ('update', '_test-srvc-type._tcp.local.', 'xxxyyy._test-srvc-type._tcp.local.'),
        ('remove', '_test-srvc-type._tcp.local.', 'xxxyyy._test-srvc-type._tcp.local.'),
    ]


@pytest.mark.asyncio
async def test_async_service_registration_without_broadcast() -> None:
    """Test that registration broadcast can be disabled."""
    zc = AsyncZeroconf(interfaces=['127.0.0.1'])
    type_ = "_test-srvc-type._tcp.local."
    name = "xxxyyy"
    registration_name = "%s.%s" % (name, type_)

    calls = []

    class MyListener(ServiceListener):
        def add_service(self, zeroconf: Zeroconf, type: str, name: str) -> None:
            calls.append(("add", type, name))

        def remove_service(self, zeroconf: Zeroconf, type: str, name: str) -> None:
            calls.append(("remove", type, name))

        def update_service(self, zeroconf: Zeroconf, type: str, name: str) -> None:
            calls.append(("update", type, name))

    listener = MyListener()
    zc.add_service_listener(type_, listener)

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
    await zc.async_register_service(info, broadcast_service=False)
    new_info = ServiceInfo(
        type_,
        registration_name,
        80,
        0,
        0,
        desc,
        "ash-2.local.",
        addresses=[socket.inet_aton("10.0.1.3")],
    )
    await zc.async_update_service(new_info, broadcast_service=False)
    await zc.async_unregister_service(new_info, broadcast_service=False)
    await asyncio.sleep(UNREGISTER_TIME / 1000 * 3)
    await zc.async_close()

    assert calls == []
