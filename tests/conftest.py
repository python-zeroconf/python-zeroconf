#!/usr/bin/env python


""" conftest for zeroconf tests. """

import threading
import unittest

import pytest

from zeroconf import _core, const


@pytest.fixture(autouse=True)
def verify_threads_ended():
    """Verify that the threads are not running after the test."""
    threads_before = frozenset(threading.enumerate())
    yield
    threads = frozenset(threading.enumerate()) - threads_before
    assert not threads


@pytest.fixture
def run_isolated():
    """Change the mDNS port to run the test in isolation."""
    with unittest.mock.patch.object(_core, "_MDNS_PORT", 5454), unittest.mock.patch.object(
        const, "_MDNS_PORT", 5454
    ):
        yield
