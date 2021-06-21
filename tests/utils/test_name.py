#!/usr/bin/env python
# -*- coding: utf-8 -*-


"""Unit tests for zeroconf._utils.name."""

import pytest

from zeroconf._utils import name as nameutils
from zeroconf import BadTypeInNameException


def test_service_type_name_overlong_type():
    """Test overlong service_type_name type."""
    with pytest.raises(BadTypeInNameException):
        nameutils.service_type_name("Tivo1._tivo-videostream._tcp.local.")
    nameutils.service_type_name("Tivo1._tivo-videostream._tcp.local.", strict=False)


def test_service_type_name_overlong_full_name():
    """Test overlong service_type_name full name."""
    long_name = "Tivo1Tivo1Tivo1Tivo1Tivo1Tivo1Tivo1Tivo1" * 100
    with pytest.raises(BadTypeInNameException):
        nameutils.service_type_name(f"{long_name}._tivo-videostream._tcp.local.")
    with pytest.raises(BadTypeInNameException):
        nameutils.service_type_name(f"{long_name}._tivo-videostream._tcp.local.", strict=False)
