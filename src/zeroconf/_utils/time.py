"""A pure python implementation of multicast DNS service discovery.

Licensed under LGPL-2.1-or-later; see COPYING for details. This file is
part of a continuously modified work; modification dates are recorded
in the project's git history.
"""

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
