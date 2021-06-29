#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for logger.py."""

import logging
from unittest.mock import patch
from zeroconf._logger import QuietLogger, set_logger_level_if_unset


def test_loading_logger():
    """Test loading logger does not change level unless it is unset."""
    log = logging.getLogger('zeroconf')
    log.setLevel(logging.CRITICAL)
    set_logger_level_if_unset()
    log = logging.getLogger('zeroconf')
    assert log.level == logging.CRITICAL

    log = logging.getLogger('zeroconf')
    log.setLevel(logging.NOTSET)
    set_logger_level_if_unset()
    log = logging.getLogger('zeroconf')
    assert log.level == logging.WARNING


def test_log_warning_once():
    """Test we only log with warning level once."""
    quiet_logger = QuietLogger()
    with patch("zeroconf._logger.log.warning") as mock_log_warning, patch(
        "zeroconf._logger.log.debug"
    ) as mock_log_debug:
        quiet_logger.log_warning_once("the warning")

    assert mock_log_warning.mock_calls
    assert not mock_log_debug.mock_calls

    with patch("zeroconf._logger.log.warning") as mock_log_warning, patch(
        "zeroconf._logger.log.debug"
    ) as mock_log_debug:
        quiet_logger.log_warning_once("the warning")

    assert not mock_log_warning.mock_calls
    assert mock_log_debug.mock_calls


def test_log_exception_warning():
    """Test we only log with warning level once."""
    quiet_logger = QuietLogger()
    with patch("zeroconf._logger.log.warning") as mock_log_warning, patch(
        "zeroconf._logger.log.debug"
    ) as mock_log_debug:
        quiet_logger.log_exception_warning("the exception warning")

    assert mock_log_warning.mock_calls
    assert not mock_log_debug.mock_calls

    with patch("zeroconf._logger.log.warning") as mock_log_warning, patch(
        "zeroconf._logger.log.debug"
    ) as mock_log_debug:
        quiet_logger.log_exception_warning("the exception warning")

    assert not mock_log_warning.mock_calls
    assert mock_log_debug.mock_calls
