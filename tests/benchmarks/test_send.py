"""Benchmark for sending packets."""

from pytest_codspeed import BenchmarkFixture

from zeroconf.asyncio import AsyncZeroconf

from .helpers import generate_packets


async def test_sending_packets(benchmark: BenchmarkFixture) -> None:
    """Benchmark sending packets."""
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"])
    await aiozc.zeroconf.async_wait_for_start()
    out = generate_packets()

    @benchmark
    def _send_packets() -> None:
        aiozc.zeroconf.async_send(out)

    await aiozc.async_close()
