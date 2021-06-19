#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for aio.py."""

import asyncio
import logging
import socket
import threading
import unittest.mock

import pytest

from zeroconf.aio import AsyncServiceInfo, AsyncZeroconf, AsyncZeroconfServiceTypes
from zeroconf import Zeroconf
from zeroconf.const import _LISTENER_TIME
from zeroconf._exceptions import BadTypeInNameException, NonUniqueNameException, ServiceNameAlreadyRegistered
from zeroconf._services import ServiceListener
from zeroconf._services.info import ServiceInfo
from zeroconf._utils.time import current_time_millis

from . import _clear_cache

log = logging.getLogger('zeroconf')
original_logging_level = logging.NOTSET


def setup_module():
    global original_logging_level
    original_logging_level = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    if original_logging_level != logging.NOTSET:
        log.setLevel(original_logging_level)


@pytest.fixture(autouse=True)
def verify_threads_ended():
    """Verify that the threads are not running after the test."""
    threads_before = frozenset(threading.enumerate())
    yield
    threads_after = frozenset(threading.enumerate())
    non_executor_threads = frozenset(
        [
            thread
            for thread in threads_after
            if "asyncio" not in thread.name and "ThreadPoolExecutor" not in thread.name
        ]
    )
    threads = non_executor_threads - threads_before
    assert not threads


@pytest.mark.asyncio
async def test_async_basic_usage() -> None:
    """Test we can create and close the instance."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_async_close_twice() -> None:
    """Test we can close twice."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    await aiozc.async_close()
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_async_with_sync_passed_in() -> None:
    """Test we can create and close the instance when passing in a sync Zeroconf."""
    zc = Zeroconf(interfaces=['127.0.0.1'])
    aiozc = AsyncZeroconf(zc=zc)
    assert aiozc.zeroconf is zc
    await aiozc.async_close()


@pytest.mark.asyncio
async def test_async_with_sync_passed_in_closed_in_async() -> None:
    """Test caller closes the sync version in async."""
    zc = Zeroconf(interfaces=['127.0.0.1'])
    aiozc = AsyncZeroconf(zc=zc)
    assert aiozc.zeroconf is zc
    zc.close()
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
    await aiozc.zeroconf.async_wait(50000)
    assert current_time_millis() - now < 3000
    await task

    now = current_time_millis()
    await aiozc.zeroconf.async_wait(50)
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
    _clear_cache(aiozc.zeroconf)
    # Generating the race condition is almost impossible
    # without patching since its a TOCTOU race
    with unittest.mock.patch("zeroconf.aio.AsyncServiceInfo._is_complete", False):
        await aiosinfo.async_request(aiozc.zeroconf, 3000)
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

    class MyListener(ServiceListener):
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
    await aiozc.zeroconf.async_wait(1)
    await aiozc.async_close()

    assert calls == [
        ('add', type_, registration_name),
        ('update', type_, registration_name),
        ('remove', type_, registration_name),
    ]


@pytest.mark.asyncio
async def test_async_context_manager() -> None:
    """Test using an async context manager."""
    type_ = "_test10-sr-type._tcp.local."
    name = "xxxyyy"
    registration_name = "%s.%s" % (name, type_)

    async with AsyncZeroconf(interfaces=['127.0.0.1']) as aiozc:
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            {'path': '/~paulsm/'},
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )
        task = await aiozc.async_register_service(info)
        await task
        aiosinfo = await aiozc.async_get_service_info(type_, registration_name)
        assert aiosinfo is not None


@pytest.mark.asyncio
async def test_async_unregister_all_services() -> None:
    """Test unregistering all services."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    type_ = "_test1-srvc-type._tcp.local."
    name = "xxxyyy"
    name2 = "abc"
    registration_name = "%s.%s" % (name, type_)
    registration_name2 = "%s.%s" % (name2, type_)

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

    tasks = []
    tasks.append(aiozc.async_get_service_info(type_, registration_name))
    tasks.append(aiozc.async_get_service_info(type_, registration_name2))
    results = await asyncio.gather(*tasks)
    assert results[0] is not None
    assert results[1] is not None

    await aiozc.async_unregister_all_services()

    tasks = []
    tasks.append(aiozc.async_get_service_info(type_, registration_name))
    tasks.append(aiozc.async_get_service_info(type_, registration_name2))
    results = await asyncio.gather(*tasks)
    assert results[0] is None
    assert results[1] is None

    # Verify we can call again
    await aiozc.async_unregister_all_services()

    await aiozc.async_close()


@pytest.mark.asyncio
async def test_async_zeroconf_service_types():
    type_ = "_test-srvc-type._tcp.local."
    name = "xxxyyy"
    registration_name = "%s.%s" % (name, type_)

    zeroconf_registrar = AsyncZeroconf(interfaces=['127.0.0.1'])
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
    task = await zeroconf_registrar.async_register_service(info)
    await task
    # Ensure we do not clear the cache until after the last broadcast is processed
    await asyncio.sleep(0.2)
    _clear_cache(zeroconf_registrar.zeroconf)
    try:
        service_types = await AsyncZeroconfServiceTypes.async_find(interfaces=['127.0.0.1'], timeout=0.5)
        assert type_ in service_types
        _clear_cache(zeroconf_registrar.zeroconf)
        service_types = await AsyncZeroconfServiceTypes.async_find(aiozc=zeroconf_registrar, timeout=0.5)
        assert type_ in service_types

    finally:
        await zeroconf_registrar.async_close()
