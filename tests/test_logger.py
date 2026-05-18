"""Unit tests for logger.py."""

from __future__ import annotations

import logging
from unittest.mock import call, patch

from zeroconf import _logger
from zeroconf._logger import _MAX_SEEN_LOGS, QuietLogger, _mark_seen, set_logger_level_if_unset


def test_loading_logger():
    """Test loading logger does not change level unless it is unset."""
    log = logging.getLogger("zeroconf")
    log.setLevel(logging.CRITICAL)
    set_logger_level_if_unset()
    log = logging.getLogger("zeroconf")
    assert log.level == logging.CRITICAL

    log = logging.getLogger("zeroconf")
    log.setLevel(logging.NOTSET)
    set_logger_level_if_unset()
    log = logging.getLogger("zeroconf")
    assert log.level == logging.WARNING


def test_log_warning_once():
    """Test we only log with warning level once."""
    _logger._seen_logs.clear()
    quiet_logger = QuietLogger()
    with (
        patch("zeroconf._logger.log.warning") as mock_log_warning,
        patch("zeroconf._logger.log.debug") as mock_log_debug,
    ):
        quiet_logger.log_warning_once("the warning")

    assert mock_log_warning.mock_calls
    assert not mock_log_debug.mock_calls

    with (
        patch("zeroconf._logger.log.warning") as mock_log_warning,
        patch("zeroconf._logger.log.debug") as mock_log_debug,
    ):
        quiet_logger.log_warning_once("the warning")

    assert not mock_log_warning.mock_calls
    assert mock_log_debug.mock_calls


def test_log_exception_warning():
    """Test we only log with warning level once."""
    _logger._seen_logs.clear()
    quiet_logger = QuietLogger()
    with (
        patch("zeroconf._logger.log.warning") as mock_log_warning,
        patch("zeroconf._logger.log.debug") as mock_log_debug,
    ):
        quiet_logger.log_exception_warning("the exception warning")

    assert mock_log_warning.mock_calls
    assert not mock_log_debug.mock_calls

    with (
        patch("zeroconf._logger.log.warning") as mock_log_warning,
        patch("zeroconf._logger.log.debug") as mock_log_debug,
    ):
        quiet_logger.log_exception_warning("the exception warning")

    assert not mock_log_warning.mock_calls
    assert mock_log_debug.mock_calls


def test_llog_exception_debug():
    """Test we only log with a trace once."""
    _logger._seen_logs.clear()
    quiet_logger = QuietLogger()
    with patch("zeroconf._logger.log.debug") as mock_log_debug:
        quiet_logger.log_exception_debug("the exception")

    assert mock_log_debug.mock_calls == [call("the exception", exc_info=True)]

    with patch("zeroconf._logger.log.debug") as mock_log_debug:
        quiet_logger.log_exception_debug("the exception")

    assert mock_log_debug.mock_calls == [call("the exception", exc_info=False)]


def test_mark_seen_absorbs_runtime_error_during_eviction() -> None:
    """Concurrent mutation can make ``iter(seen)`` raise ``RuntimeError``.

    Free-threaded (3.14t) and multi-instance sync callers share
    ``_seen_logs``; if another thread mutates it between ``iter()``
    and ``next()`` the iterator raises ``RuntimeError``.
    ``_mark_seen`` must absorb that and still insert the new key.
    """

    class RacyDict(dict[str, None]):
        def __iter__(self):  # type: ignore[override]
            raise RuntimeError("dictionary changed size during iteration")

    seen: dict[str, None] = RacyDict()
    for i in range(_MAX_SEEN_LOGS):
        seen[f"k-{i}"] = None
    assert _mark_seen(seen, "new-key") is True
    assert "new-key" in seen


def test_mark_seen_drains_drift_above_cap() -> None:
    """``_mark_seen`` drains a drifted-over-cap dict back to the cap.

    Concurrent inserts on the free-threaded build can leave the dict
    transiently above ``_MAX_SEEN_LOGS`` (e.g. two threads both passed
    the ``len < cap`` check and both inserted). The next non-racing
    call must drain the accumulated overshoot, not just evict one
    entry — otherwise the cap silently inflates with thread count.
    """
    seen: dict[str, None] = {}
    drift = 10
    for i in range(_MAX_SEEN_LOGS + drift):
        seen[f"k-{i}"] = None
    assert len(seen) == _MAX_SEEN_LOGS + drift
    assert _mark_seen(seen, "new-key") is True
    assert len(seen) == _MAX_SEEN_LOGS
    assert "new-key" in seen
    for i in range(drift + 1):
        assert f"k-{i}" not in seen


def test_mark_seen_drains_drift_on_hit_path() -> None:
    """``_mark_seen`` drains drift even when ``key`` is already cached.

    A hit-heavy workload after a contention burst (e.g. the same
    exception text deduplicated repeatedly) must still correct the
    overshoot — otherwise the dict can sit permanently above the cap
    until a miss happens to come along.
    """
    seen: dict[str, None] = {}
    drift = 10
    for i in range(_MAX_SEEN_LOGS + drift):
        seen[f"k-{i}"] = None
    # Hit on a non-oldest key — survives the drift drain.
    hit_key = f"k-{_MAX_SEEN_LOGS}"
    assert _mark_seen(seen, hit_key) is False
    assert len(seen) == _MAX_SEEN_LOGS
    assert hit_key in seen
    for i in range(drift):
        assert f"k-{i}" not in seen


def test_seen_logs_is_bounded() -> None:
    """``_seen_logs`` stays at the cap and evicts oldest-first (FIFO)."""
    _logger._seen_logs.clear()
    overflow = 5
    with patch("zeroconf._logger.log.warning"), patch("zeroconf._logger.log.debug"):
        for i in range(_MAX_SEEN_LOGS + overflow):
            QuietLogger.log_warning_once(f"warning-{i}")
    assert len(_logger._seen_logs) == _MAX_SEEN_LOGS
    for i in range(overflow):
        assert f"warning-{i}" not in _logger._seen_logs
    for i in range(_MAX_SEEN_LOGS, _MAX_SEEN_LOGS + overflow):
        assert f"warning-{i}" in _logger._seen_logs


def test_log_exception_once():
    """Test we only log with warning level once."""
    _logger._seen_logs.clear()
    quiet_logger = QuietLogger()
    exc = Exception()
    with (
        patch("zeroconf._logger.log.warning") as mock_log_warning,
        patch("zeroconf._logger.log.debug") as mock_log_debug,
    ):
        quiet_logger.log_exception_once(exc, "the exceptional exception warning")

    assert mock_log_warning.mock_calls
    assert not mock_log_debug.mock_calls

    with (
        patch("zeroconf._logger.log.warning") as mock_log_warning,
        patch("zeroconf._logger.log.debug") as mock_log_debug,
    ):
        quiet_logger.log_exception_once(exc, "the exceptional exception warning")

    assert not mock_log_warning.mock_calls
    assert mock_log_debug.mock_calls
