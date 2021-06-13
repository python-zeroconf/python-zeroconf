#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf.core """

import itertools
import logging
import threading
import time
import unittest
import unittest.mock


import pytest
import zeroconf as r
from zeroconf import core

log = logging.getLogger('zeroconf')
original_logging_level = logging.NOTSET


@pytest.fixture(autouse=True)
def verify_threads_ended():
    """Verify that the threads are not running after the test."""
    threads_before = frozenset(threading.enumerate())
    yield
    threads = frozenset(threading.enumerate()) - threads_before
    assert not threads


def setup_module():
    global original_logging_level
    original_logging_level = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    if original_logging_level != logging.NOTSET:
        log.setLevel(original_logging_level)


class TestReaper(unittest.TestCase):
    @unittest.mock.patch.object(core, "_CACHE_CLEANUP_INTERVAL", 10)
    def test_reaper(self):
        zeroconf = core.Zeroconf(interfaces=['127.0.0.1'])
        cache = zeroconf.cache
        original_entries = list(itertools.chain(*[cache.entries_with_name(name) for name in cache.names()]))
        record_with_10s_ttl = r.DNSAddress('a', r._TYPE_SOA, r._CLASS_IN, 10, b'a')
        record_with_1s_ttl = r.DNSAddress('a', r._TYPE_SOA, r._CLASS_IN, 1, b'b')
        zeroconf.cache.add(record_with_10s_ttl)
        zeroconf.cache.add(record_with_1s_ttl)
        entries_with_cache = list(itertools.chain(*[cache.entries_with_name(name) for name in cache.names()]))
        time.sleep(1)
        with zeroconf.engine.condition:
            zeroconf.engine._notify()
        time.sleep(0.1)
        entries = list(itertools.chain(*[cache.entries_with_name(name) for name in cache.names()]))
        zeroconf.close()
        assert entries != original_entries
        assert entries_with_cache != original_entries
        assert record_with_10s_ttl in entries
        assert record_with_1s_ttl not in entries
