#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for zeroconf._utils.aio."""

import asyncio
import contextlib

import pytest

from zeroconf._utils import aio as aioutils


@pytest.mark.asyncio
async def test_get_running_loop_from_async() -> None:
    """Test we can get the event loop."""
    assert isinstance(aioutils.get_running_loop(), asyncio.AbstractEventLoop)


def test_get_running_loop_no_loop() -> None:
    """Test we get None when there is no loop running."""
    assert aioutils.get_running_loop() is None


@pytest.mark.asyncio
async def test_wait_event_or_timeout_times_out() -> None:
    """Test wait_event_or_timeout will timeout."""
    test_cond = asyncio.Condition()
    async with test_cond:
        await aioutils.wait_event_or_timeout(test_cond, 0.1)

    async def _hold_condition():
        async with test_cond:
            await test_cond.wait()

    task = asyncio.ensure_future(_hold_condition())
    await asyncio.sleep(0.1)

    async def _async_wait_or_timeout():
        async with test_cond:
            await aioutils.wait_event_or_timeout(test_cond, 0.1)

    # Test high lock contention
    await asyncio.gather(*[_async_wait_or_timeout() for _ in range(100)])

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task
