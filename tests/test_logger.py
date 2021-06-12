#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for logger.py."""

from unittest.mock import patch
from zeroconf.logger import QuietLogger


def test_log_warning_once():
    """Test we only log with warning level once."""
    quiet_logger = QuietLogger()
    with patch("zeroconf.logger.log.warning") as mock_log_warning, patch(
        "zeroconf.logger.log.debug"
    ) as mock_log_debug:
        quiet_logger.log_warning_once("the warning")

    assert mock_log_warning.mock_calls
    assert not mock_log_debug.mock_calls

    with patch("zeroconf.logger.log.warning") as mock_log_warning, patch(
        "zeroconf.logger.log.debug"
    ) as mock_log_debug:
        quiet_logger.log_warning_once("the warning")

    assert not mock_log_warning.mock_calls
    assert mock_log_debug.mock_calls


def test_log_exception_warning():
    """Test we only log with warning level once."""
    quiet_logger = QuietLogger()
    with patch("zeroconf.logger.log.warning") as mock_log_warning, patch(
        "zeroconf.logger.log.debug"
    ) as mock_log_debug:
        quiet_logger.log_exception_warning("the exception warning")

    assert mock_log_warning.mock_calls
    assert not mock_log_debug.mock_calls

    with patch("zeroconf.logger.log.warning") as mock_log_warning, patch(
        "zeroconf.logger.log.debug"
    ) as mock_log_debug:
        quiet_logger.log_exception_warning("the exception warning")

    assert not mock_log_warning.mock_calls
    assert mock_log_debug.mock_calls
