"""A pure python implementation of multicast DNS service discovery.

Licensed under LGPL-2.1-or-later; see COPYING for details. This file is
part of a continuously modified work; modification dates are recorded
in the project's git history.
"""

from __future__ import annotations

import enum
from collections.abc import Callable
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .._core import Zeroconf


@enum.unique
class ServiceStateChange(enum.Enum):
    Added = 1
    Removed = 2
    Updated = 3


class ServiceListener:
    def add_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        raise NotImplementedError

    def remove_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        raise NotImplementedError

    def update_service(self, zc: Zeroconf, type_: str, name: str) -> None:
        raise NotImplementedError


class Signal:
    __slots__ = ("_handlers",)

    def __init__(self) -> None:
        self._handlers: list[Callable[..., None]] = []

    def fire(self, **kwargs: Any) -> None:
        for h in self._handlers[:]:
            h(**kwargs)

    @property
    def registration_interface(self) -> SignalRegistrationInterface:
        return SignalRegistrationInterface(self._handlers)


class SignalRegistrationInterface:
    __slots__ = ("_handlers",)

    def __init__(self, handlers: list[Callable[..., None]]) -> None:
        self._handlers = handlers

    def register_handler(self, handler: Callable[..., None]) -> SignalRegistrationInterface:
        self._handlers.append(handler)
        return self

    def unregister_handler(self, handler: Callable[..., None]) -> SignalRegistrationInterface:
        self._handlers.remove(handler)
        return self
