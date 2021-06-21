#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for logger.py."""

import logging


import zeroconf._logger


def test_logger_sets_level_to_warning_if_missing():
    """Test logging.WARNING is set when loading if NONSET."""
    log = logging.getLogger('zeroconf')
    assert log.level == logging.WARNING
