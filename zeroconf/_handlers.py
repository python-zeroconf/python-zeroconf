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

import itertools
from typing import List, Optional, TYPE_CHECKING, Union

from ._dns import DNSAddress, DNSIncoming, DNSOutgoing, DNSPointer, DNSQuestion, DNSRecord
from ._logger import log
from ._utils.time import current_time_millis
from .const import (
    _CLASS_IN,
    _DNS_OTHER_TTL,
    _FLAGS_AA,
    _FLAGS_QR_RESPONSE,
    _SERVICE_TYPE_ENUMERATION_NAME,
    _TYPE_A,
    _TYPE_ANY,
    _TYPE_PTR,
    _TYPE_SRV,
    _TYPE_TXT,
)
from .services import (
    RecordUpdateListener,
)
from .services.registry import ServiceRegistry


if TYPE_CHECKING:
    # https://github.com/PyCQA/pylint/issues/3525
    from ._core import Zeroconf  # pylint: disable=cyclic-import


class QueryHandler:
    """Query the ServiceRegistry."""

    def __init__(self, registry: ServiceRegistry):
        """Init the query handler."""
        self.registry = registry

    def _answer_service_type_enumeration_query(self, msg: DNSIncoming, out: DNSOutgoing) -> None:
        """Provide an answer to a service type enumeration query.

        https://datatracker.ietf.org/doc/html/rfc6763#section-9
        """
        for stype in self.registry.get_types():
            out.add_answer(
                msg,
                DNSPointer(
                    _SERVICE_TYPE_ENUMERATION_NAME,
                    _TYPE_PTR,
                    _CLASS_IN,
                    _DNS_OTHER_TTL,
                    stype,
                ),
            )

    def _answer_ptr_query(self, msg: DNSIncoming, out: DNSOutgoing, question: DNSQuestion) -> None:
        """Answer a PTR query."""
        for service in self.registry.get_infos_type(question.name.lower()):
            out.add_answer(msg, service.dns_pointer())
            # Add recommended additional answers according to
            # https://tools.ietf.org/html/rfc6763#section-12.1.
            out.add_additional_answer(service.dns_service())
            out.add_additional_answer(service.dns_text())
            for dns_address in service.dns_addresses():
                out.add_additional_answer(dns_address)

    def _answer_non_ptr_query(self, msg: DNSIncoming, out: DNSOutgoing, question: DNSQuestion) -> None:
        """Answer a query any query other then PTR.

        Add answer(s) for A, AAAA, SRV, or TXT queries.
        """
        name_to_find = question.name.lower()
        # Answer A record queries for any service addresses we know
        if question.type in (_TYPE_A, _TYPE_ANY):
            for service in self.registry.get_infos_server(name_to_find):
                for dns_address in service.dns_addresses():
                    out.add_answer(msg, dns_address)

        service = self.registry.get_info_name(name_to_find)  # type: ignore
        if service is None:
            return

        if question.type in (_TYPE_SRV, _TYPE_ANY):
            out.add_answer(msg, service.dns_service())
        if question.type in (_TYPE_TXT, _TYPE_ANY):
            out.add_answer(msg, service.dns_text())
        if question.type == _TYPE_SRV:
            for dns_address in service.dns_addresses():
                out.add_additional_answer(dns_address)

    def response(self, msg: DNSIncoming, unicast: bool) -> Optional[DNSOutgoing]:
        """Deal with incoming query packets. Provides a response if possible."""
        if unicast:
            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA, multicast=False)
            for question in msg.questions:
                out.add_question(question)
        else:
            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)

        for question in msg.questions:
            if question.type == _TYPE_PTR:
                if question.name.lower() == _SERVICE_TYPE_ENUMERATION_NAME:
                    self._answer_service_type_enumeration_query(msg, out)
                else:
                    self._answer_ptr_query(msg, out, question)
                continue

            self._answer_non_ptr_query(msg, out, question)

        if out is not None and out.answers:
            out.id = msg.id
            return out

        return None


class RecordManager:
    """Process records into the cache and notify listeners."""

    def __init__(self, zeroconf: 'Zeroconf') -> None:
        """Init the record manager."""
        self.zc = zeroconf
        self.cache = zeroconf.cache
        self.listeners: List[RecordUpdateListener] = []

    def updates(self, now: float, rec: List[DNSRecord]) -> None:
        """Used to notify listeners of new information that has updated
        a record.

        This method must be called before the cache is updated.
        """
        for listener in self.listeners:
            listener.update_records(self.zc, now, rec)

    def updates_complete(self) -> None:
        """Used to notify listeners of new information that has updated
        a record.

        This method must be called after the cache is updated.
        """
        for listener in self.listeners:
            listener.update_records_complete()
        self.zc.notify_all()

    def updates_from_response(self, msg: DNSIncoming) -> None:
        """Deal with incoming response packets.  All answers
        are held in the cache, and listeners are notified."""
        updates: List[DNSRecord] = []
        address_adds: List[DNSAddress] = []
        other_adds: List[DNSRecord] = []
        removes: List[DNSRecord] = []
        now = current_time_millis()
        for record in msg.answers:

            updated = True

            if record.unique:  # https://tools.ietf.org/html/rfc6762#section-10.2
                # rfc6762#section-10.2 para 2
                # Since unique is set, all old records with that name, rrtype,
                # and rrclass that were received more than one second ago are declared
                # invalid, and marked to expire from the cache in one second.
                for entry in self.cache.get_all_by_details(record.name, record.type, record.class_):
                    if entry == record:
                        updated = False
                    if record.created - entry.created > 1000 and entry not in msg.answers:
                        removes.append(entry)

            expired = record.is_expired(now)
            maybe_entry = self.cache.get(record)
            if not expired:
                if maybe_entry is not None:
                    maybe_entry.reset_ttl(record)
                else:
                    if isinstance(record, DNSAddress):
                        address_adds.append(record)
                    else:
                        other_adds.append(record)
                if updated:
                    updates.append(record)
            elif maybe_entry is not None:
                updates.append(record)
                removes.append(record)

        if not updates and not address_adds and not other_adds and not removes:
            return

        self.updates(now, updates)
        # The cache adds must be processed AFTER we trigger
        # the updates since we compare existing data
        # with the new data and updating the cache
        # ahead of update_record will cause listeners
        # to miss changes
        #
        # We must process address adds before non-addresses
        # otherwise a fetch of ServiceInfo may miss an address
        # because it thinks the cache is complete
        #
        # The cache is processed under the context manager to ensure
        # that any ServiceBrowser that is going to call
        # zc.get_service_info will see the cached value
        # but ONLY after all the record updates have been
        # processsed.
        self.cache.add_records(itertools.chain(address_adds, other_adds))
        # Removes are processed last since
        # ServiceInfo could generate an un-needed query
        # because the data was not yet populated.
        self.cache.remove_records(removes)
        self.updates_complete()

    def add_listener(
        self, listener: RecordUpdateListener, question: Optional[Union[DNSQuestion, List[DNSQuestion]]]
    ) -> None:
        """Adds a listener for a given question.  The listener will have
        its update_record method called when information is available to
        answer the question(s)."""
        self.listeners.append(listener)

        if question is not None:
            now = current_time_millis()
            records = []
            questions = [question] if isinstance(question, DNSQuestion) else question
            for single_question in questions:
                for record in self.cache.entries_with_name(single_question.name):
                    if single_question.answered_by(record) and not record.is_expired(now):
                        records.append(record)
            if records:
                listener.update_records(self.zc, now, records)
                listener.update_records_complete()

        self.zc.notify_all()

    def remove_listener(self, listener: RecordUpdateListener) -> None:
        """Removes a listener."""
        try:
            self.listeners.remove(listener)
            self.zc.notify_all()
        except ValueError as e:
            log.exception('Failed to remove listener: %r', e)
