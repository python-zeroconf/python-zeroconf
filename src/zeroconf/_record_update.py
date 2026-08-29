from __future__ import annotations

from ._dns import DNSRecord

_DNSRecord = DNSRecord


class RecordUpdate:
    __slots__ = ("new", "old")

    def __init__(self, new: DNSRecord, old: DNSRecord | None = None) -> None:
        """RecordUpdate represents a change in a DNS record."""
        self._fast_init(new, old)

    def _fast_init(self, new: _DNSRecord, old: _DNSRecord | None) -> None:
        """Fast init for RecordUpdate."""
        self.new = new
        self.old = old

    def __getitem__(self, index: int) -> DNSRecord | None:
        """Get the new or old record."""
        if index == 0:
            return self.new
        if index == 1:
            return self.old
        raise IndexError(index)
