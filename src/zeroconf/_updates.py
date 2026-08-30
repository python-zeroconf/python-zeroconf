"""A pure python implementation of multicast DNS service discovery.

Licensed under LGPL-2.1-or-later; see COPYING for details. This file is
part of a continuously modified work; modification dates are recorded
in the project's git history.
"""

from __future__ import annotations

from typing import TYPE_CHECKING

from ._dns import DNSRecord
from ._record_update import RecordUpdate

if TYPE_CHECKING:
    from ._core import Zeroconf


float_ = float


class RecordUpdateListener:
    """Base call for all record listeners.

    All listeners passed to async_add_listener should use RecordUpdateListener
    as a base class. In the future it will be required.
    """

    def async_update_records(self, zc: Zeroconf, now: float_, records: list[RecordUpdate]) -> None:
        """Update multiple records in one shot.

        All records that are received in a single packet are passed
        to update_records.

        This implementation is a compatibility shim to ensure older code
        that uses RecordUpdateListener as a base class will continue to
        get calls to update_record. This method will raise
        NotImplementedError in a future version.

        At this point the cache will not have the new records

        Records are passed as a list of RecordUpdate.  This
        allows consumers of async_update_records to avoid cache lookups.

        This method will be run in the event loop.
        """
        for record in records:
            self.update_record(zc, now, record.new)

    def async_update_records_complete(self) -> None:
        """Called when a record update has completed for all handlers.

        At this point the cache will have the new records.

        This method will be run in the event loop.
        """

    def update_record(  # pylint: disable=no-self-use
        self, zc: Zeroconf, now: float, record: DNSRecord
    ) -> None:
        """Update a single record.

        This method is deprecated and will be removed in a future version.
        update_records should be implemented instead.
        """
        raise RuntimeError("update_record is deprecated and will be removed in a future version.")
