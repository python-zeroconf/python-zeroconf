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
from typing import List, Optional, Set, TYPE_CHECKING, Tuple, Union

from ._cache import DNSCache
from ._dns import DNSAddress, DNSIncoming, DNSOutgoing, DNSPointer, DNSQuestion, DNSRecord
from ._logger import log
from ._services import RecordUpdateListener
from ._services.registry import ServiceRegistry
from ._utils.net import IPVersion
from ._utils.time import current_time_millis
from .const import (
    _CLASS_IN,
    _DNS_OTHER_TTL,
    _EXPIRE_REFRESH_TIME_PERCENT,
    _FLAGS_AA,
    _FLAGS_QR_RESPONSE,
    _MDNS_PORT,
    _SERVICE_TYPE_ENUMERATION_NAME,
    _TYPE_A,
    _TYPE_AAAA,
    _TYPE_ANY,
    _TYPE_PTR,
    _TYPE_SRV,
    _TYPE_TXT,
)

_TYPE_TO_IP_VERSION = {_TYPE_A: IPVersion.V4Only, _TYPE_AAAA: IPVersion.V6Only, _TYPE_ANY: IPVersion.All}

if TYPE_CHECKING:
    # https://github.com/PyCQA/pylint/issues/3525
    from ._core import Zeroconf  # pylint: disable=cyclic-import


class QueryHandler:
    """Query the ServiceRegistry."""

    def __init__(self, registry: ServiceRegistry, cache: DNSCache):
        """Init the query handler."""
        self.registry = registry
        self.cache = cache

    def _answer_service_type_enumeration_query(self) -> Set[DNSRecord]:
        """Provide an answer to a service type enumeration query.

        https://datatracker.ietf.org/doc/html/rfc6763#section-9
        """
        return set(
            [
                DNSPointer(_SERVICE_TYPE_ENUMERATION_NAME, _TYPE_PTR, _CLASS_IN, _DNS_OTHER_TTL, stype)
                for stype in self.registry.get_types()
            ]
        )

    def _answer_question(
        self, msg: DNSIncoming, question: DNSQuestion
    ) -> Tuple[Set[DNSRecord], Set[DNSRecord]]:
        answers: Set[DNSRecord] = set()
        additionals: Set[DNSRecord] = set()
        type_ = question.type

        if type_ in (_TYPE_PTR, _TYPE_ANY):
            for service in self.registry.get_infos_type(question.name):
                # Add recommended additional answers according to
                # https://tools.ietf.org/html/rfc6763#section-12.1.
                dns_pointer = service.dns_pointer()
                if not dns_pointer.suppressed_by(msg):
                    answers.add(service.dns_pointer())
                    additionals.add(service.dns_service())
                    additionals.add(service.dns_text())
                    additionals.update(service.dns_addresses())

        if type_ in (_TYPE_A, _TYPE_AAAA, _TYPE_ANY):
            for service in self.registry.get_infos_server(question.name):
                for dns_address in service.dns_addresses(version=_TYPE_TO_IP_VERSION[type_]):
                    if not dns_address.suppressed_by(msg):
                        answers.add(dns_address)

        if type_ in (_TYPE_SRV, _TYPE_TXT, _TYPE_ANY):
            service = self.registry.get_info_name(question.name)  # type: ignore
            if service is not None:
                if type_ in (_TYPE_SRV, _TYPE_ANY):
                    dns_service = service.dns_service()
                    if not dns_service.suppressed_by(msg):
                        answers.add(service.dns_service())
                        additionals.update(service.dns_addresses())
                if type_ in (_TYPE_TXT, _TYPE_ANY):
                    dns_text = service.dns_text()
                    if not dns_text.suppressed_by(msg):
                        answers.add(service.dns_text())

        return answers, additionals

    def response(  # pylint: disable=unused-argument
        self, msg: DNSIncoming, addr: Optional[str], port: int
    ) -> Tuple[Optional[DNSOutgoing], Optional[DNSOutgoing]]:
        """Deal with incoming query packets. Provides a response if possible."""
        unicast_out: Optional[DNSOutgoing] = None
        multicast_out: Optional[DNSOutgoing] = None

        is_probe = msg.num_authorities > 0
        unicast_answers: Set[DNSRecord] = set()
        unicast_additionals: Set[DNSRecord] = set()
        multicast_answers: Set[DNSRecord] = set()
        multicast_additionals: Set[DNSRecord] = set()
        unicast_source = port != _MDNS_PORT
        now = current_time_millis()

        for question in msg.questions:
            if question.type == _TYPE_PTR and question.name.lower() == _SERVICE_TYPE_ENUMERATION_NAME:
                answers = self._answer_service_type_enumeration_query()
                additionals: Set[DNSRecord] = set()
            else:
                answers, additionals = self._answer_question(msg, question)

            if not answers and not additionals:
                continue

            if not unicast_source and question.unicast:
                # QU bit set
                for answer in answers:
                    if is_probe:
                        unicast_answers.add(answer)
                    if not self._has_multicast_record_recently(answer, now):
                        multicast_answers.add(answer)
                    elif not is_probe:
                        unicast_answers.add(answer)
                for additional in additionals:
                    if is_probe:
                        unicast_additionals.add(additional)
                    if not self._has_multicast_record_recently(additional, now):
                        multicast_additionals.add(additional)
                    elif not is_probe:
                        unicast_additionals.add(additional)
            else:
                if unicast_source:
                    # Unicast source, always send back to source and multicast
                    unicast_answers.update(answers)
                    unicast_additionals.update(additionals)
                # Standard Multicast
                multicast_answers.update(answers)
                multicast_additionals.update(additionals)

        if unicast_answers or unicast_additionals:
            unicast_additionals -= unicast_answers
            unicast_out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA, multicast=False, id_=msg.id)
            if unicast_source:
                for question in msg.questions:
                    unicast_out.add_question(question)
            self._add_unicast_answers_to_outgoing(unicast_out, unicast_answers, unicast_additionals)

        if multicast_answers or multicast_additionals:
            multicast_additionals -= multicast_answers
            multicast_out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA, id_=msg.id)
            self._add_multicast_answers_to_outgoing(
                multicast_out, multicast_answers, multicast_additionals, is_probe, now
            )

        return unicast_out, multicast_out

    def _has_multicast_record_recently(self, record: DNSRecord, now: float) -> bool:
        """Check to see if a record has been multicasted recently."""
        maybe_entry = self.cache.get(record)
        return bool(maybe_entry and maybe_entry.get_expiration_time(_EXPIRE_REFRESH_TIME_PERCENT) > now)

    def _has_multicast_record_in_last_second(self, record: DNSRecord, now: float) -> bool:
        """Remove answers that were just broadcast

        Protect the network against excessive packet flooding
        https://datatracker.ietf.org/doc/html/rfc6762#section-14
        """
        maybe_entry = self.cache.get(record)
        return bool(maybe_entry and now - maybe_entry.created < 1000)

    def _add_multicast_answers_to_outgoing(
        self,
        out: DNSOutgoing,
        answers: Set[DNSRecord],
        additionals: Set[DNSRecord],
        is_probe: bool,
        now: float,
    ) -> None:
        """Add answers and additionals to a DNSOutgoing."""
        for answer in answers:
            if is_probe or not self._has_multicast_record_in_last_second(answer, now):
                out.add_answer_at_time(answer, 0)
        for additional in additionals:
            if is_probe or not self._has_multicast_record_in_last_second(additional, now):
                out.add_additional_answer(additional)

    def _add_unicast_answers_to_outgoing(
        self, out: DNSOutgoing, answers: Set[DNSRecord], additionals: Set[DNSRecord]
    ) -> None:
        """Add answers and additionals to a DNSOutgoing."""
        for answer in answers:
            out.add_answer_at_time(answer, 0)
        for additional in additionals:
            out.add_additional_answer(additional)


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
