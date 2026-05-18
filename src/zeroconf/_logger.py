"""Multicast DNS Service Discovery for Python, v0.14-wmcbrine
    )
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

from __future__ import annotations

import logging
import sys
from typing import Any

log = logging.getLogger(__name__.split(".", maxsplit=1)[0])
log.addHandler(logging.NullHandler())


def set_logger_level_if_unset() -> None:
    if log.level == logging.NOTSET:
        log.setLevel(logging.WARN)


set_logger_level_if_unset()


_MAX_SEEN_LOGS = 512
_seen_logs: dict[str, None] = {}


def _evict_oldest(seen: dict[str, None]) -> bool:
    """Pop the oldest entry from ``seen``; return False if it raced.

    Individual dict ops (``pop`` with a default, ``next``) are atomic
    on the free-threaded build, but the compound ``iter`` → ``next``
    used to pick the FIFO victim can raise ``RuntimeError`` if
    another thread mutates the dict between the two ops. The caller
    breaks its drain loop on False so concurrent mutation can't make
    it spin.
    """
    try:
        seen.pop(next(iter(seen)), None)
    except (RuntimeError, StopIteration):
        return False
    return True


def _mark_seen(seen: dict[str, None], key: str) -> bool:
    """Record ``key`` in ``seen`` and return True if it was newly added.

    Bounds the dict so callers passing attacker-influenced keys (peer
    addresses, packet offsets) cannot grow it without bound. Evicts
    the oldest entries on overflow (dict preserves insertion order on
    Python 3.7+), so ``_MAX_SEEN_LOGS`` is a recency window.

    The dict is shared across all ``Zeroconf`` instances in the
    process; on the free-threaded build (3.14t) and under multi-
    instance sync use, callers can race the ``len < cap`` check and
    both insert, leaving the dict transiently above the cap. The
    drain loop runs on every call (steady-state-at-cap hits are a
    single ``len`` + compare past the membership check because the
    helper short-circuits) so a contention burst is corrected by the
    next caller regardless of whether it's a hit or a miss.
    """
    inserting = key not in seen
    # Hit (``inserting`` is False): drain only if drifted above cap.
    # Miss (``inserting`` is True): drain to ``cap - 1`` to make room
    # for the new key. Bool subtracts as 0/1 to pick the right limit.
    while len(seen) > _MAX_SEEN_LOGS - inserting and _evict_oldest(seen):
        pass
    if inserting:
        seen[key] = None
    return inserting


class QuietLogger:
    @classmethod
    def log_exception_warning(cls, *logger_data: Any) -> None:
        first_time = _mark_seen(_seen_logs, str(sys.exc_info()[1]))
        logger = log.warning if first_time else log.debug
        logger(*(logger_data or ["Exception occurred"]), exc_info=True)

    @classmethod
    def log_exception_debug(cls, *logger_data: Any) -> None:
        first_time = _mark_seen(_seen_logs, str(sys.exc_info()[1]))
        log.debug(*(logger_data or ["Exception occurred"]), exc_info=first_time)

    @classmethod
    def log_warning_once(cls, *args: Any) -> None:
        logger = log.warning if _mark_seen(_seen_logs, args[0]) else log.debug
        logger(*args)

    @classmethod
    def log_exception_once(cls, exc: Exception, *args: Any) -> None:
        logger = log.warning if _mark_seen(_seen_logs, args[0]) else log.debug
        logger(*args, exc_info=exc)
