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
from typing import Any, ClassVar

log = logging.getLogger(__name__.split(".", maxsplit=1)[0])
log.addHandler(logging.NullHandler())


def set_logger_level_if_unset() -> None:
    if log.level == logging.NOTSET:
        log.setLevel(logging.WARN)


set_logger_level_if_unset()


_MAX_SEEN_LOGS = 256


class QuietLogger:
    _seen_logs: ClassVar[set[str]] = set()

    @classmethod
    def _mark_seen(cls, key: str) -> bool:
        """Record ``key`` and return True if it was newly added."""
        if key in cls._seen_logs:
            return False
        # Keys can carry caller-supplied fields (peer addresses, packet
        # offsets); clear when full so a malicious peer can't grow the
        # set without bound.
        if len(cls._seen_logs) >= _MAX_SEEN_LOGS:
            cls._seen_logs.clear()
        cls._seen_logs.add(key)
        return True

    @classmethod
    def log_exception_warning(cls, *logger_data: Any) -> None:
        first_time = cls._mark_seen(str(sys.exc_info()[1]))
        logger = log.warning if first_time else log.debug
        logger(*(logger_data or ["Exception occurred"]), exc_info=True)

    @classmethod
    def log_exception_debug(cls, *logger_data: Any) -> None:
        first_time = cls._mark_seen(str(sys.exc_info()[1]))
        log.debug(*(logger_data or ["Exception occurred"]), exc_info=first_time)

    @classmethod
    def log_warning_once(cls, *args: Any) -> None:
        logger = log.warning if cls._mark_seen(args[0]) else log.debug
        logger(*args)

    @classmethod
    def log_exception_once(cls, exc: Exception, *args: Any) -> None:
        logger = log.warning if cls._mark_seen(args[0]) else log.debug
        logger(*args, exc_info=exc)
