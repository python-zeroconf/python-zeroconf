#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for logger.py."""

import logging


def test_loading_logger():
    """Test loading logger does not change level unless it is unset."""
    log = logging.getLogger('zeroconf')
    log.setLevel(logging.CRITICAL)
    exec('import zeroconf._logger')
    log = logging.getLogger('zeroconf')
    assert log.level == logging.CRITICAL
