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
