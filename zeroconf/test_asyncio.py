#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for async.py."""

import asyncio
import socket

import pytest

from . import (
    BadTypeInNameException,
    NonUniqueNameException,
    ServiceInfo,
    ServiceListener,
    ServiceNameAlreadyRegistered,
    Zeroconf,
    _REGISTER_TIME,
    _UNREGISTER_TIME,
)
from .asyncio import AsyncZeroconf


@pytest.mark.asyncio
async def test_async_basic_usage() -> None:
    """Test we can create and close the instance."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_async_service_registration() -> None:
    """Test registering services broadcasts the registration by default."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
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
    aiozc.zeroconf.add_service_listener(type_, listener)

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
    await aiozc.async_register_service(info)
    await asyncio.sleep(_REGISTER_TIME / 1000 * 3)
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
    await aiozc.async_update_service(new_info)
    await asyncio.sleep(_REGISTER_TIME / 1000 * 3)

    await aiozc.async_unregister_service(new_info)
    await asyncio.sleep(_UNREGISTER_TIME / 1000 * 3)
    await aiozc.async_close()

    assert calls == [
        ('add', '_test-srvc-type._tcp.local.', 'xxxyyy._test-srvc-type._tcp.local.'),
        ('update', '_test-srvc-type._tcp.local.', 'xxxyyy._test-srvc-type._tcp.local.'),
        ('remove', '_test-srvc-type._tcp.local.', 'xxxyyy._test-srvc-type._tcp.local.'),
    ]


@pytest.mark.asyncio
async def test_async_service_registration_name_conflict() -> None:
    """Test registering services throws on name conflict."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
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
    await aiozc.async_register_service(info)
    await asyncio.sleep(_REGISTER_TIME / 1000 * 3)

    with pytest.raises(NonUniqueNameException):
        await aiozc.async_register_service(info)

    with pytest.raises(ServiceNameAlreadyRegistered):
        await aiozc.async_register_service(info, cooperating_responders=True)

    await aiozc.async_close()


@pytest.mark.asyncio
async def test_async_service_registration_name_does_not_match_type() -> None:
    """Test registering services throws when the name does not match the type."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
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
    info.type = "_wrong._tcp.local."
    with pytest.raises(BadTypeInNameException):
        await aiozc.async_register_service(info)
    await aiozc.async_close()
