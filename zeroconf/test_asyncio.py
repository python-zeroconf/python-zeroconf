#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for async.py."""

import asyncio
import socket
import unittest.mock

import pytest

from . import (
    BadTypeInNameException,
    NonUniqueNameException,
    ServiceInfo,
    ServiceListener,
    ServiceNameAlreadyRegistered,
    Zeroconf,
    _LISTENER_TIME,
    current_time_millis,
)
from .asyncio import AsyncServiceInfo, AsyncServiceListener, AsyncZeroconf


@pytest.mark.asyncio
async def test_async_basic_usage() -> None:
    """Test we can create and close the instance."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_async_with_sync_passed_in() -> None:
    """Test we can create and close the instance when passing in a sync Zeroconf."""
    zc = Zeroconf(interfaces=['127.0.0.1'])
    aiozc = AsyncZeroconf(zc=zc)
    assert aiozc.zeroconf is zc
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_async_service_registration() -> None:
    """Test registering services broadcasts the registration by default."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    type_ = "_test1-srvc-type._tcp.local."
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
    task = await aiozc.async_register_service(info)
    await task
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
    task = await aiozc.async_update_service(new_info)
    await task
    task = await aiozc.async_unregister_service(new_info)
    await task
    await aiozc.async_close()

    assert calls == [
        ('add', type_, registration_name),
        ('update', type_, registration_name),
        ('remove', type_, registration_name),
    ]


@pytest.mark.asyncio
async def test_async_service_registration_name_conflict() -> None:
    """Test registering services throws on name conflict."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    type_ = "_test-srvc2-type._tcp.local."
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
    task = await aiozc.async_register_service(info)
    await task

    with pytest.raises(NonUniqueNameException):
        task = await aiozc.async_register_service(info)
        await task

    with pytest.raises(ServiceNameAlreadyRegistered):
        task = await aiozc.async_register_service(info, cooperating_responders=True)
        await task

    conflicting_info = ServiceInfo(
        type_,
        registration_name,
        80,
        0,
        0,
        desc,
        "ash-3.local.",
        addresses=[socket.inet_aton("10.0.1.3")],
    )

    with pytest.raises(NonUniqueNameException):
        task = await aiozc.async_register_service(conflicting_info)
        await task

    await aiozc.async_close()


@pytest.mark.asyncio
async def test_async_service_registration_name_does_not_match_type() -> None:
    """Test registering services throws when the name does not match the type."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    type_ = "_test-srvc3-type._tcp.local."
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
        task = await aiozc.async_register_service(info)
        await task
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_async_tasks() -> None:
    """Test awaiting broadcast tasks"""

    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    type_ = "_test-srvc4-type._tcp.local."
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
    task = await aiozc.async_register_service(info)
    assert isinstance(task, asyncio.Task)
    await task

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
    task = await aiozc.async_update_service(new_info)
    assert isinstance(task, asyncio.Task)
    await task

    task = await aiozc.async_unregister_service(new_info)
    assert isinstance(task, asyncio.Task)
    await task

    await aiozc.async_close()

    assert calls == [
        ('add', type_, registration_name),
        ('update', type_, registration_name),
        ('remove', type_, registration_name),
    ]


@pytest.mark.asyncio
async def test_async_wait_unblocks_on_update() -> None:
    """Test async_wait will unblock on update."""

    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    type_ = "_test-srvc4-type._tcp.local."
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
    task = await aiozc.async_register_service(info)

    # Should unblock due to update from the
    # registration
    now = current_time_millis()
    await aiozc.async_wait(50000)
    assert current_time_millis() - now < 3000
    await task

    now = current_time_millis()
    await aiozc.async_wait(50)
    assert current_time_millis() - now < 1000

    await aiozc.async_close()


@pytest.mark.asyncio
async def test_service_info_async_request() -> None:
    """Test registering services broadcasts and query with AsyncServceInfo.async_request."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    type_ = "_test1-srvc-type._tcp.local."
    name = "xxxyyy"
    name2 = "abc"
    registration_name = "%s.%s" % (name, type_)
    registration_name2 = "%s.%s" % (name2, type_)

    # Start a tasks BEFORE the registration that will keep trying
    # and see the registration a bit later
    get_service_info_task1 = asyncio.ensure_future(aiozc.async_get_service_info(type_, registration_name))
    await asyncio.sleep(_LISTENER_TIME / 1000 / 2)
    get_service_info_task2 = asyncio.ensure_future(aiozc.async_get_service_info(type_, registration_name))

    desc = {'path': '/~paulsm/'}
    info = ServiceInfo(
        type_,
        registration_name,
        80,
        0,
        0,
        desc,
        "ash-1.local.",
        addresses=[socket.inet_aton("10.0.1.2")],
    )
    info2 = ServiceInfo(
        type_,
        registration_name2,
        80,
        0,
        0,
        desc,
        "ash-5.local.",
        addresses=[socket.inet_aton("10.0.1.5")],
    )
    tasks = []
    tasks.append(await aiozc.async_register_service(info))
    tasks.append(await aiozc.async_register_service(info2))
    await asyncio.gather(*tasks)

    aiosinfo = await get_service_info_task1
    assert aiosinfo is not None
    assert aiosinfo.addresses == [socket.inet_aton("10.0.1.2")]

    aiosinfo = await get_service_info_task2
    assert aiosinfo is not None
    assert aiosinfo.addresses == [socket.inet_aton("10.0.1.2")]

    aiosinfo = await aiozc.async_get_service_info(type_, registration_name)
    assert aiosinfo is not None
    assert aiosinfo.addresses == [socket.inet_aton("10.0.1.2")]

    new_info = ServiceInfo(
        type_,
        registration_name,
        80,
        0,
        0,
        desc,
        "ash-2.local.",
        addresses=[socket.inet_aton("10.0.1.3"), socket.inet_pton(socket.AF_INET6, "6001:db8::1")],
    )

    task = await aiozc.async_update_service(new_info)
    await task

    aiosinfo = await aiozc.async_get_service_info(type_, registration_name)
    assert aiosinfo is not None
    assert aiosinfo.addresses == [socket.inet_aton("10.0.1.3")]

    aiosinfos = await asyncio.gather(
        aiozc.async_get_service_info(type_, registration_name),
        aiozc.async_get_service_info(type_, registration_name2),
    )
    assert aiosinfos[0] is not None
    assert aiosinfos[0].addresses == [socket.inet_aton("10.0.1.3")]
    assert aiosinfos[1] is not None
    assert aiosinfos[1].addresses == [socket.inet_aton("10.0.1.5")]

    aiosinfo = AsyncServiceInfo(type_, registration_name)
    zc_cache = aiozc.zeroconf.cache
    for name in zc_cache.names():
        for record in zc_cache.entries_with_name(name):
            zc_cache.remove(record)
    # Generating the race condition is almost impossible
    # without patching since its a TOCTOU race
    with unittest.mock.patch("zeroconf.asyncio.AsyncServiceInfo._is_complete", False):
        await aiosinfo.async_request(aiozc, 3000)
    assert aiosinfo is not None
    assert aiosinfo.addresses == [socket.inet_aton("10.0.1.3")]

    task = await aiozc.async_unregister_service(new_info)
    await task

    aiosinfo = await aiozc.async_get_service_info(type_, registration_name)
    assert aiosinfo is None

    await aiozc.async_close()


@pytest.mark.asyncio
async def test_async_service_browser() -> None:
    """Test AsyncServiceBrowser."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    type_ = "_test9-srvc-type._tcp.local."
    name = "xxxyyy"
    registration_name = "%s.%s" % (name, type_)

    calls = []

    with pytest.raises(NotImplementedError):
        AsyncServiceListener().add_service(aiozc, "_type", "name._type")

    with pytest.raises(NotImplementedError):
        AsyncServiceListener().remove_service(aiozc, "_type", "name._type")

    with pytest.raises(NotImplementedError):
        AsyncServiceListener().update_service(aiozc, "_type", "name._type")

    class MyListener(AsyncServiceListener):
        def add_service(self, aiozc: AsyncZeroconf, type: str, name: str) -> None:
            calls.append(("add", type, name))

        def remove_service(self, aiozc: AsyncZeroconf, type: str, name: str) -> None:
            calls.append(("remove", type, name))

        def update_service(self, aiozc: AsyncZeroconf, type: str, name: str) -> None:
            calls.append(("update", type, name))

    listener = MyListener()
    await aiozc.async_add_service_listener(type_, listener)

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
    task = await aiozc.async_register_service(info)
    await task
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
    task = await aiozc.async_update_service(new_info)
    await task
    task = await aiozc.async_unregister_service(new_info)
    await task
    await aiozc.async_close()

    assert calls[0] == ('add', type_, registration_name)
