"""Benchmarks for zeroconf._utils.ipaddress address objects."""

from __future__ import annotations

from pytest_codspeed import BenchmarkFixture

from zeroconf._utils.ipaddress import ZeroconfIPv4Address, ZeroconfIPv6Address

_IPV4_STRS = [f"10.{(i >> 8) & 0xFF}.{i & 0xFF}.1" for i in range(1000)]
_IPV6_BYTES = [(0x20010DB8 << 96 | i).to_bytes(16, "big") for i in range(1000)]


def test_create_ipv4_addresses(benchmark: BenchmarkFixture) -> None:
    """Benchmark constructing 1000 distinct IPv4 address objects."""

    @benchmark
    def _create() -> None:
        for addr in _IPV4_STRS:
            ZeroconfIPv4Address(addr)


def test_create_ipv6_addresses(benchmark: BenchmarkFixture) -> None:
    """Benchmark constructing 1000 distinct IPv6 address objects."""

    @benchmark
    def _create() -> None:
        for addr in _IPV6_BYTES:
            ZeroconfIPv6Address(addr)


def test_hash_ipv4_address(benchmark: BenchmarkFixture) -> None:
    """Benchmark hashing the same IPv4 address object 1000 times."""
    addr = ZeroconfIPv4Address("10.0.0.1")

    @benchmark
    def _hash() -> None:
        for _ in range(1000):
            hash(addr)


def test_hash_ipv6_address(benchmark: BenchmarkFixture) -> None:
    """Benchmark hashing the same IPv6 address object 1000 times."""
    addr = ZeroconfIPv6Address(b"\x20\x01\x0d\xb8\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x00\x01")

    @benchmark
    def _hash() -> None:
        for _ in range(1000):
            hash(addr)
