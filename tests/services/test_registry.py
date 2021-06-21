#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for zeroconf._services.registry."""

import unittest
import socket

import zeroconf as r
from zeroconf import ServiceInfo


class TestServiceRegistry(unittest.TestCase):
    def test_only_register_once(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
        )

        registry = r.ServiceRegistry()
        registry.add(info)
        self.assertRaises(r.ServiceNameAlreadyRegistered, registry.add, info)
        registry.remove(info)
        registry.add(info)

    def test_unregister_multiple_times(self):
        """Verify we can unregister a service multiple times.

        In production unregister_service and unregister_all_services
        may happen at the same time during shutdown. We want to treat
        this as non-fatal since its expected to happen and it is unlikely
        that the callers know about each other.
        """
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
        )

        registry = r.ServiceRegistry()
        registry.add(info)
        self.assertRaises(r.ServiceNameAlreadyRegistered, registry.add, info)
        registry.remove(info)
        registry.remove(info)

    def test_lookups(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
        )

        registry = r.ServiceRegistry()
        registry.add(info)

        assert registry.get_service_infos() == [info]
        assert registry.get_info_name(registration_name) == info
        assert registry.get_infos_type(type_) == [info]
        assert registry.get_infos_server("ash-2.local.") == [info]
        assert registry.get_types() == [type_]

    def test_lookups_upper_case_by_lower_case(self):
        type_ = "_test-SRVC-type._tcp.local."
        name = "Xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_, registration_name, 80, 0, 0, desc, "ASH-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
        )

        registry = r.ServiceRegistry()
        registry.add(info)

        assert registry.get_service_infos() == [info]
        assert registry.get_info_name(registration_name.lower()) == info
        assert registry.get_infos_type(type_.lower()) == [info]
        assert registry.get_infos_server("ash-2.local.") == [info]
        assert registry.get_types() == [type_.lower()]

    def test_lookups_lower_case_by_upper_case(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = "%s.%s" % (name, type_)

        desc = {'path': '/~paulsm/'}
        info = ServiceInfo(
            type_, registration_name, 80, 0, 0, desc, "ash-2.local.", addresses=[socket.inet_aton("10.0.1.2")]
        )

        registry = r.ServiceRegistry()
        registry.add(info)

        assert registry.get_service_infos() == [info]
        assert registry.get_info_name(registration_name.upper()) == info
        assert registry.get_infos_type(type_.upper()) == [info]
        assert registry.get_infos_server("ASH-2.local.") == [info]
        assert registry.get_types() == [type_]
