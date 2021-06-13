#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" conftest for zeroconf tests. """

import threading

import pytest


@pytest.fixture(autouse=True)
def verify_threads_ended():
    """Verify that the threads are not running after the test."""
    threads_before = frozenset(threading.enumerate())
    yield
    threads = frozenset(threading.enumerate()) - threads_before
    assert not threads
