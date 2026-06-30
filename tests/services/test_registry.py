"""Unit tests for zeroconf._services.registry."""

from __future__ import annotations

import socket
import unittest

import zeroconf as r
from zeroconf import ServiceInfo


class TestServiceRegistry(unittest.TestCase):
    def test_only_register_once(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = f"{name}.{type_}"

        desc = {"path": "/~paulsm/"}
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )

        registry = r.ServiceRegistry()
        registry.async_add(info)
        self.assertRaises(r.ServiceNameAlreadyRegistered, registry.async_add, info)
        registry.async_remove(info)
        registry.async_add(info)

    def test_register_same_server(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        name2 = "xxxyyy2"
        registration_name = f"{name}.{type_}"
        registration_name2 = f"{name2}.{type_}"

        desc = {"path": "/~paulsm/"}
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            desc,
            "same.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )
        info2 = ServiceInfo(
            type_,
            registration_name2,
            80,
            0,
            0,
            desc,
            "same.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )
        registry = r.ServiceRegistry()
        registry.async_add(info)
        registry.async_add(info2)
        assert registry.async_get_infos_server("same.local.") == [info, info2]
        registry.async_remove(info)
        assert registry.async_get_infos_server("same.local.") == [info2]
        registry.async_remove(info2)
        assert registry.async_get_infos_server("same.local.") == []

    def test_unregister_multiple_times(self):
        """Verify we can unregister a service multiple times.

        In production unregister_service and unregister_all_services
        may happen at the same time during shutdown. We want to treat
        this as non-fatal since its expected to happen and it is unlikely
        that the callers know about each other.
        """
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = f"{name}.{type_}"

        desc = {"path": "/~paulsm/"}
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )

        registry = r.ServiceRegistry()
        registry.async_add(info)
        self.assertRaises(r.ServiceNameAlreadyRegistered, registry.async_add, info)
        registry.async_remove(info)
        registry.async_remove(info)

    def test_lookups(self):
        type_ = "_test-srvc-type._tcp.local."
        name = "xxxyyy"
        registration_name = f"{name}.{type_}"

        desc = {"path": "/~paulsm/"}
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )

        registry = r.ServiceRegistry()
        registry.async_add(info)

        assert registry.async_get_service_infos() == [info]
        assert registry.async_get_info_name(registration_name) == info
        assert registry.async_get_infos_type(type_) == [info]
        assert registry.async_get_infos_server("ash-2.local.") == [info]
        assert registry.async_get_types() == [type_]

    def test_lookups_upper_case_by_lower_case(self):
        type_ = "_test-SRVC-type._tcp.local."
        name = "Xxxyyy"
        registration_name = f"{name}.{type_}"

        desc = {"path": "/~paulsm/"}
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            desc,
            "ASH-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )

        registry = r.ServiceRegistry()
        registry.async_add(info)

        assert registry.async_get_service_infos() == [info]
        assert registry.async_get_info_name(registration_name.lower()) == info
        assert registry.async_get_infos_type(type_.lower()) == [info]
        assert registry.async_get_infos_server("ash-2.local.") == [info]
        assert registry.async_get_types() == [type_.lower()]

    def test_empty_buckets_are_removed_when_last_entry_is_removed(self):
        type_ = "_test-srvc-type._tcp.local."
        registration_name = f"xxxyyy.{type_}"
        desc = {"path": "/~paulsm/"}
        info = ServiceInfo(
            type_,
            registration_name,
            80,
            0,
            0,
            desc,
            "ash-2.local.",
            addresses=[socket.inet_aton("10.0.1.2")],
        )

        registry = r.ServiceRegistry()
        registry.async_add(info)
        registry.async_remove(info)

        assert type_.lower() not in registry.types
        assert "ash-2.local." not in registry.servers
        assert registry.async_get_types() == []

    def test_bulk_remove_preserves_remaining_insertion_order(self):
        type_ = "_test-srvc-type._tcp.local."
        server = "shared.local."
        desc = {"path": "/~paulsm/"}
        infos = [
            ServiceInfo(
                type_,
                f"svc{i}.{type_}",
                80,
                0,
                0,
                desc,
                server,
                addresses=[socket.inet_aton("10.0.1.2")],
            )
            for i in range(20)
        ]

        registry = r.ServiceRegistry()
        for info in infos:
            registry.async_add(info)

        # Remove every other entry in one bulk call.
        to_remove = [infos[i] for i in range(0, 20, 2)]
        registry.async_remove(to_remove)

        expected = [infos[i] for i in range(1, 20, 2)]
        assert registry.async_get_infos_type(type_) == expected
        assert registry.async_get_infos_server(server) == expected

    def test_bulk_remove_then_readd_under_same_key(self):
        """Re-adding after the bucket was deleted must rebuild it cleanly."""
        type_ = "_test-srvc-type._tcp.local."
        server = "ash-2.local."
        desc = {"path": "/~paulsm/"}
        info = ServiceInfo(
            type_,
            f"only.{type_}",
            80,
            0,
            0,
            desc,
            server,
            addresses=[socket.inet_aton("10.0.1.2")],
        )

        registry = r.ServiceRegistry()
        registry.async_add(info)
        registry.async_remove(info)
        assert type_.lower() not in registry.types
        registry.async_add(info)
        assert registry.async_get_infos_type(type_) == [info]
        assert registry.async_get_infos_server(server) == [info]
