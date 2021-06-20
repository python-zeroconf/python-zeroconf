#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for logger.py."""

import logging

logging.basicConfig()


def test_logger_does_not_override_preset_debug():
    """Test logging.DEBUG is preserved when loading."""
    log = logging.getLogger('zeroconf')
    log.setLevel(logging.DEBUG)
    from zeroconf._logger import QuietLogger

    assert log.level == logging.DEBUG
