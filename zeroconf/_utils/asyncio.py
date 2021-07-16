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
from typing import Any, Awaitable, Coroutine, List, Optional, Set, cast

from .time import millis_to_seconds
from ..const import _LOADED_SYSTEM_TIMEOUT

# The combined timeouts should be lower than _CLOSE_TIMEOUT + _WAIT_FOR_LOOP_TASKS_TIMEOUT
_TASK_AWAIT_TIMEOUT = 1
_GET_ALL_TASKS_TIMEOUT = 3
_WAIT_FOR_LOOP_TASKS_TIMEOUT = 3  # Must be larger than _TASK_AWAIT_TIMEOUT


def get_best_available_queue() -> queue.Queue:
    """Create the best available queue type."""
    if hasattr(queue, "SimpleQueue"):
        return queue.SimpleQueue()  # type: ignore  # pylint: disable=all
    return queue.Queue()


# Switch to asyncio.wait_for once https://bugs.python.org/issue39032 is fixed
async def wait_event_or_timeout(event: asyncio.Event, timeout: float) -> None:
    """Wait for an event or timeout."""
    loop = asyncio.get_event_loop()
    future = loop.create_future()

    def _handle_timeout_or_wait_complete(*_: Any) -> None:
        if not future.done():
            future.set_result(None)

    timer_handle = loop.call_later(timeout, _handle_timeout_or_wait_complete)
    event_wait = loop.create_task(event.wait())
    event_wait.add_done_callback(_handle_timeout_or_wait_complete)

    try:
        await future
    finally:
        timer_handle.cancel()
        if not event_wait.done():
            event_wait.cancel()
        with contextlib.suppress(asyncio.CancelledError):
            await event_wait


async def _async_get_all_tasks(loop: asyncio.AbstractEventLoop) -> List[asyncio.Task]:
    """Return all tasks running."""
    await asyncio.sleep(0)  # flush out any call_soon_threadsafe
    # If there are multiple event loops running, all_tasks is not
    # safe EVEN WHEN CALLED FROM THE EVENTLOOP
    # under PyPy so we have to try a few times.
    for _ in range(3):
        with contextlib.suppress(RuntimeError):
            if hasattr(asyncio, 'all_tasks'):
                return asyncio.all_tasks(loop)  # type: ignore  # pylint: disable=no-member
            return asyncio.Task.all_tasks(loop)  # type: ignore  # pylint: disable=no-member
    return []


async def _wait_for_loop_tasks(wait_tasks: Set[asyncio.Task]) -> None:
    """Wait for the event loop thread we started to shutdown."""
    await asyncio.wait(wait_tasks, timeout=_TASK_AWAIT_TIMEOUT)


async def await_awaitable(aw: Awaitable) -> None:
    """Wait on an awaitable and the task it returns."""
    task = await aw
    await task


def run_coro_with_timeout(aw: Coroutine, loop: asyncio.AbstractEventLoop, timeout: float) -> Any:
    """Run a coroutine with a timeout."""
    return asyncio.run_coroutine_threadsafe(aw, loop).result(
        millis_to_seconds(timeout) + _LOADED_SYSTEM_TIMEOUT
    )


def shutdown_loop(loop: asyncio.AbstractEventLoop) -> None:
    """Wait for pending tasks and stop an event loop."""
    pending_tasks = set(
        asyncio.run_coroutine_threadsafe(_async_get_all_tasks(loop), loop).result(_GET_ALL_TASKS_TIMEOUT)
    )
    pending_tasks -= set(task for task in pending_tasks if task.done())
    if pending_tasks:
        asyncio.run_coroutine_threadsafe(_wait_for_loop_tasks(pending_tasks), loop).result(
            _WAIT_FOR_LOOP_TASKS_TIMEOUT
        )
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
