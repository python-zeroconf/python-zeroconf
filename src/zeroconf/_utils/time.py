from __future__ import annotations

import time

_float = float


def current_time_millis() -> _float:
    """Monotonic clock reading in milliseconds.

    Must stay aligned with asyncio.loop.time(); the backing clock is an
    implementation detail and may change.
    """
    return time.monotonic() * 1000


def millis_to_seconds(millis: _float) -> _float:
    """Convert milliseconds to seconds."""
    return millis / 1000.0
