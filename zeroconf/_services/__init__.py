""" Multicast DNS Service Discovery for Python, v0.14-wmcbrine
    Copyright 2003 Paul Scott-Murphy, 2014 William McBrine

    This module provides a framework for the use of DNS Service Discovery
    using IP multicast.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
    USA
"""

import enum
from typing import Any, Callable, List, TYPE_CHECKING

from .._dns import DNSRecord

if TYPE_CHECKING:
    # https://github.com/PyCQA/pylint/issues/3525
    from .._core import Zeroconf  # pylint: disable=cyclic-import


@enum.unique
class ServiceStateChange(enum.Enum):
    Added = 1
    Removed = 2
    Updated = 3


class ServiceListener:
    def add_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()

    def remove_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()

    def update_service(self, zc: 'Zeroconf', type_: str, name: str) -> None:
        raise NotImplementedError()


class Signal:
    def __init__(self) -> None:
        self._handlers: List[Callable[..., None]] = []

    def fire(self, **kwargs: Any) -> None:
        for h in list(self._handlers):
            h(**kwargs)

    @property
    def registration_interface(self) -> 'SignalRegistrationInterface':
        return SignalRegistrationInterface(self._handlers)


class SignalRegistrationInterface:
    def __init__(self, handlers: List[Callable[..., None]]) -> None:
        self._handlers = handlers

    def register_handler(self, handler: Callable[..., None]) -> 'SignalRegistrationInterface':
        self._handlers.append(handler)
        return self

    def unregister_handler(self, handler: Callable[..., None]) -> 'SignalRegistrationInterface':
        self._handlers.remove(handler)
        return self


class RecordUpdateListener:
    def update_record(  # pylint: disable=no-self-use
        self, zc: 'Zeroconf', now: float, record: DNSRecord
    ) -> None:
        """Update a single record.

        This method is deprecated and will be removed in a future version.
        update_records should be implemented instead.
        """
        raise RuntimeError("update_record is deprecated and will be removed in a future version.")

    def async_update_records(self, zc: 'Zeroconf', now: float, records: List[DNSRecord]) -> None:
        """Update multiple records in one shot.

        All records that are received in a single packet are passed
        to update_records.

        This implementation is a compatiblity shim to ensure older code
        that uses RecordUpdateListener as a base class will continue to
        get calls to update_record. This method will raise
        NotImplementedError in a future version.

        At this point the cache will not have the new records

        This method will be run in the event loop.
        """
        for record in records:
            self.update_record(zc, now, record)

    def async_update_records_complete(self) -> None:
        """Called when a record update has completed for all handlers.

        At this point the cache will have the new records.

        This method will be run in the event loop.
        """
