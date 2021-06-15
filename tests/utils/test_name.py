#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for zeroconf._utils.name."""

import pytest

from zeroconf._utils import name as nameutils
from zeroconf import BadTypeInNameException


def test_service_type_name():
    """Test overlong service_type_name."""
    with pytest.raises(BadTypeInNameException):
        nameutils.service_type_name("Tivo1._tivo-videostream._tcp.local.")
    nameutils.service_type_name("Tivo1._tivo-videostream._tcp.local.", strict=False)
