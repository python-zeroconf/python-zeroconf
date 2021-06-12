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
from typing import Optional, cast


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
