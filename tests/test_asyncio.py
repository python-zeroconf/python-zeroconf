#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for asyncio.py."""

import pytest
import threading

from zeroconf.asyncio import AsyncZeroconf


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
