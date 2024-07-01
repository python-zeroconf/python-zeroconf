"""Benchmark for AsyncZeroconf."""

import asyncio
import time

from zeroconf.asyncio import AsyncZeroconf

iterations = 10000


async def _create_destroy(count: int) -> None:
    for _ in range(count):
        async with AsyncZeroconf() as zc:
            await zc.zeroconf.async_wait_for_start()


async def _run() -> None:
    start = time.perf_counter()
    await _create_destroy(iterations)
    duration = time.perf_counter() - start
    print(f"Creating and destroying {iterations} Zeroconf instances took {duration} seconds")


asyncio.run(_run())
