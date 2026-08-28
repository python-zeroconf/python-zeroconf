"""Benchmarks for ServiceRegistry add/remove/read under a shared type and server."""

from __future__ import annotations

import socket

from pytest_codspeed import BenchmarkFixture

from zeroconf import ServiceInfo
from zeroconf._services.registry import ServiceRegistry

_TYPE = "_bench._tcp.local."
_SERVER = "bench.local."
_COUNT = 500


def _make_infos(count: int) -> list[ServiceInfo]:
    return [
        ServiceInfo(
            _TYPE,
            f"svc{i}.{_TYPE}",
            80,
            0,
            0,
            {"path": "/"},
            _SERVER,
            addresses=[socket.inet_aton("10.0.1.2")],
        )
        for i in range(count)
    ]


def test_registry_bulk_add(benchmark: BenchmarkFixture) -> None:
    """Registering many services that share one type and server."""
    infos = _make_infos(_COUNT)

    @benchmark
    def _add() -> None:
        registry = ServiceRegistry()
        for info in infos:
            registry.async_add(info)


def test_registry_bulk_remove(benchmark: BenchmarkFixture) -> None:
    """Registration plus bulk unregistration; subtract test_registry_bulk_add for the removal cost."""
    infos = _make_infos(_COUNT)

    @benchmark
    def _remove() -> None:
        registry = ServiceRegistry()
        for info in infos:
            registry.async_add(info)
        registry.async_remove(infos)


def test_registry_get_infos_type(benchmark: BenchmarkFixture) -> None:
    """Reading back every entry indexed under one shared type."""
    registry = ServiceRegistry()
    for info in _make_infos(_COUNT):
        registry.async_add(info)

    @benchmark
    def _get() -> None:
        registry.async_get_infos_type(_TYPE)
