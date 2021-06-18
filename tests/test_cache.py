#!/usr/bin/env python
# -*- coding: utf-8 -*-


""" Unit tests for zeroconf._cache. """

import logging
import unittest
import unittest.mock

import zeroconf as r
from zeroconf import const

log = logging.getLogger('zeroconf')
original_logging_level = logging.NOTSET


def setup_module():
    global original_logging_level
    original_logging_level = log.level
    log.setLevel(logging.DEBUG)


def teardown_module():
    if original_logging_level != logging.NOTSET:
        log.setLevel(original_logging_level)


class TestDNSCache(unittest.TestCase):
    def test_order(self):
        record1 = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'a')
        record2 = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'b')
        cache = r.DNSCache()
        cache.async_add(record1)
        cache.async_add(record2)
        entry = r.DNSEntry('a', const._TYPE_SOA, const._CLASS_IN)
        cached_record = cache.get(entry)
        assert cached_record == record2

    def test_cache_empty_does_not_leak_memory_by_leaving_empty_list(self):
        record1 = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'a')
        record2 = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'b')
        cache = r.DNSCache()
        cache.async_add(record1)
        cache.async_add(record2)
        assert 'a' in cache.cache
        cache.async_remove(record1)
        cache.async_remove(record2)
        assert 'a' not in cache.cache

    def test_cache_empty_multiple_calls(self):
        record1 = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'a')
        record2 = r.DNSAddress('a', const._TYPE_SOA, const._CLASS_IN, 1, b'b')
        cache = r.DNSCache()
        cache.async_add(record1)
        cache.async_add(record2)
        assert 'a' in cache.cache
        cache.async_remove(record1)
        cache.async_remove(record2)
        assert 'a' not in cache.cache


# These functions have been seen in other projects so
# we try to maintain a stable API for all the threadsafe getters
class TestDNSCacheAPI(unittest.TestCase):
    def test_get(self):
        record1 = r.DNSAddress('a', const._TYPE_A, const._CLASS_IN, 1, b'a')
        record2 = r.DNSAddress('a', const._TYPE_A, const._CLASS_IN, 1, b'b')
        cache = r.DNSCache()
        cache.async_add(record1)
        cache.async_add(record2)
        assert cache.get(record1) == record1
        assert cache.get(record2) == record2

    def test_get_by_details(self):
        record1 = r.DNSAddress('a', const._TYPE_A, const._CLASS_IN, 1, b'a')
        record2 = r.DNSAddress('a', const._TYPE_A, const._CLASS_IN, 1, b'b')
        cache = r.DNSCache()
        cache.async_add(record1)
        cache.async_add(record2)
        assert cache.get_by_details('a', const._TYPE_A, const._CLASS_IN) == record2

    def test_get_all_by_details(self):
        record1 = r.DNSAddress('a', const._TYPE_A, const._CLASS_IN, 1, b'a')
        record2 = r.DNSAddress('a', const._TYPE_A, const._CLASS_IN, 1, b'b')
        cache = r.DNSCache()
        cache.async_add(record1)
        cache.async_add(record2)
        assert set(cache.get_all_by_details('a', const._TYPE_A, const._CLASS_IN)) == set([record1, record2])

    def test_entries_with_server(self):
        record1 = r.DNSService(
            'irrelevant', const._TYPE_SRV, const._CLASS_IN, const._DNS_HOST_TTL, 0, 0, 85, 'ab'
        )
        record2 = r.DNSService(
            'irrelevant', const._TYPE_SRV, const._CLASS_IN, const._DNS_HOST_TTL, 0, 0, 80, 'ab'
        )
        cache = r.DNSCache()
        cache.async_add(record1)
        cache.async_add(record2)
        assert set(cache.entries_with_server('ab')) == set([record1, record2])

    def test_entries_with_name(self):
        record1 = r.DNSService(
            'irrelevant', const._TYPE_SRV, const._CLASS_IN, const._DNS_HOST_TTL, 0, 0, 85, 'ab'
        )
        record2 = r.DNSService(
            'irrelevant', const._TYPE_SRV, const._CLASS_IN, const._DNS_HOST_TTL, 0, 0, 80, 'ab'
        )
        cache = r.DNSCache()
        cache.async_add(record1)
        cache.async_add(record2)
        assert set(cache.entries_with_name('irrelevant')) == set([record1, record2])

    def test_current_entry_with_name_and_alias(self):
        record1 = r.DNSPointer(
            'irrelevant', const._TYPE_PTR, const._CLASS_IN, const._DNS_OTHER_TTL, 'x.irrelevant'
        )
        record2 = r.DNSPointer(
            'irrelevant', const._TYPE_PTR, const._CLASS_IN, const._DNS_OTHER_TTL, 'y.irrelevant'
        )
        cache = r.DNSCache()
        cache.async_add(record1)
        cache.async_add(record2)
        assert cache.current_entry_with_name_and_alias('irrelevant', 'x.irrelevant') == record1

    def test_entries_with_name(self):
        record1 = r.DNSService(
            'irrelevant', const._TYPE_SRV, const._CLASS_IN, const._DNS_HOST_TTL, 0, 0, 85, 'ab'
        )
        record2 = r.DNSService(
            'irrelevant', const._TYPE_SRV, const._CLASS_IN, const._DNS_HOST_TTL, 0, 0, 80, 'ab'
        )
        cache = r.DNSCache()
        cache.async_add(record1)
        cache.async_add(record2)
        assert cache.names() == ['irrelevant']
