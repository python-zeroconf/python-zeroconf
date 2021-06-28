#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for zeroconf._utils.aio."""

import asyncio
import contextlib
import threading
import time
from unittest.mock import patch

import pytest

from zeroconf._utils import aio as aioutils


@pytest.mark.asyncio
async def test_async_get_all_tasks() -> None:
    """Test we can get all tasks in the event loop.

    We make sure we handle RuntimeError here as
    this is not thread safe under PyPy
    """
    await aioutils._async_get_all_tasks(aioutils.get_running_loop())
    if not hasattr(asyncio, 'all_tasks'):
        return
    with patch("zeroconf._utils.aio.asyncio.all_tasks", side_effect=RuntimeError):
        await aioutils._async_get_all_tasks(aioutils.get_running_loop())


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
    test_event = asyncio.Event()
    await aioutils.wait_event_or_timeout(test_event, 0.1)

    task = asyncio.ensure_future(test_event.wait())
    await asyncio.sleep(0.1)

    async def _async_wait_or_timeout():
        await aioutils.wait_event_or_timeout(test_event, 0.1)

    # Test high lock contention
    await asyncio.gather(*[_async_wait_or_timeout() for _ in range(100)])

    task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await task


def test_shutdown_loop() -> None:
    """Test shutting down an event loop."""
    loop = None
    loop_thread_ready = threading.Event()

    def _run_loop() -> None:
        nonlocal loop
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        loop_thread_ready.set()
        loop.run_forever()

    loop_thread = threading.Thread(target=_run_loop, daemon=True)
    loop_thread.start()
    loop_thread_ready.wait()

    aioutils.shutdown_loop(loop)
    for _ in range(5):
        if not loop.is_running():
            break
        time.sleep(0.05)

    assert loop.is_running() is False
