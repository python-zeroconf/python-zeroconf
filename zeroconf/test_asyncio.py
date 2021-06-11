#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for asyncio.py."""


import pytest

from .asyncio import AsyncZeroconf


@pytest.mark.asyncio
async def test_async_basic_usage() -> None:
    """Test we can create and close the instance."""
    aiozc = AsyncZeroconf(interfaces=['127.0.0.1'])
    await aiozc.async_close()
