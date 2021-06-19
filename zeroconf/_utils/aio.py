""" Multicast DNS Service Discovery for Python, v0.14-wmcbrine
    Copyright 2003 Paul Scott-Murphy, 2014 William McBrine

    This module provides a framework for the use of DNS Service Discovery
    using IP multicast.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
    USA
"""

import asyncio
import contextlib
import queue
from typing import Optional, Set, cast


def get_best_available_queue() -> queue.Queue:
    """Create the best available queue type."""
    if hasattr(queue, "SimpleQueue"):
        return queue.SimpleQueue()  # type: ignore  # pylint: disable=all
    return queue.Queue()


# Switch to asyncio.wait_for once https://bugs.python.org/issue39032 is fixed
async def wait_condition_or_timeout(condition: asyncio.Condition, timeout: float) -> None:
    """Wait for a condition or timeout."""
    loop = asyncio.get_event_loop()
    future = loop.create_future()

    def _handle_timeout() -> None:
        if not future.done():
            future.set_result(None)

    timer_handle = loop.call_later(timeout, _handle_timeout)
    condition_wait = loop.create_task(condition.wait())

    def _handle_wait_complete(_: asyncio.Task) -> None:
        if not future.done():
            future.set_result(None)

    condition_wait.add_done_callback(_handle_wait_complete)

    try:
        await future
    finally:
        timer_handle.cancel()
        if not condition_wait.done():
            condition_wait.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await condition_wait


async def _get_all_tasks(loop: asyncio.AbstractEventLoop) -> Set[asyncio.Task]:
    """Return all tasks running."""
    await asyncio.sleep(0)  # flush out any call_soon_threadsafe
    if hasattr(asyncio, 'all_tasks'):
        return cast(Set[asyncio.Task], asyncio.all_tasks(loop))  # type: ignore  # pylint: disable=no-member
    return cast(Set[asyncio.Task], asyncio.Task.all_tasks(loop))  # type: ignore  # pylint: disable=no-member


async def _wait_for_loop_tasks(wait_tasks: Set[asyncio.Task]) -> None:
    """Wait for the event loop thread we started to shutdown."""
    await asyncio.wait(wait_tasks, timeout=1)


def shutdown_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Wait for pending tasks and stop an event loop."""
    pending_tasks = asyncio.run_coroutine_threadsafe(_get_all_tasks(loop), loop).result()
    done_tasks = set(task for task in pending_tasks if not task.done())
    pending_tasks -= done_tasks
    if pending_tasks:
        asyncio.run_coroutine_threadsafe(_wait_for_loop_tasks(pending_tasks), loop).result()
    loop.call_soon_threadsafe(loop.stop)


# Remove the call to _get_running_loop once we drop python 3.6 support
def get_running_loop() -> Optional[asyncio.AbstractEventLoop]:
    """Check if an event loop is already running."""
    with contextlib.suppress(RuntimeError):
        if hasattr(asyncio, "get_running_loop"):
            return cast(
                asyncio.AbstractEventLoop,
                asyncio.get_running_loop(),  # type: ignore  # pylint: disable=no-member  # noqa
            )
        return asyncio._get_running_loop()  # pylint: disable=no-member,protected-access
    return None
