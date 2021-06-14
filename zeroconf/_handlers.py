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
import itertools
from typing import Dict, List, Optional, Set, TYPE_CHECKING, Tuple, Union

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


@enum.unique
class RecordSetKeys(enum.Enum):
    Answers = 1
    Additionals = 2


# Switch to a TypedDict once Python 3.8 is the minimum supported version
_RecordSetType = Dict[RecordSetKeys, Set[DNSRecord]]


class _QueryResponse:
    """A pair for unicast and multicast DNSOutgoing responses."""

    def __init__(self, cache: DNSCache, msg: DNSIncoming, ucast_source: bool) -> None:
        """Build a query response."""
        self._msg = msg
        self._ucast_source = ucast_source
        self._is_probe = msg.num_authorities > 0
        self._now = current_time_millis()
        self._cache = cache
        self._ucast: _RecordSetType = {RecordSetKeys.Answers: set(), RecordSetKeys.Additionals: set()}
        self._mcast: _RecordSetType = {RecordSetKeys.Answers: set(), RecordSetKeys.Additionals: set()}

    def add_qu_question_response(
        self,
        answers: Set[DNSRecord],
        additionals: Set[DNSRecord],
    ) -> None:
        """Generate a response to a multicast QU query."""
        self._add_qu_question_response_to_target(answers, RecordSetKeys.Answers)
        self._add_qu_question_response_to_target(additionals, RecordSetKeys.Additionals)

    def _add_qu_question_response_to_target(self, target: Set[DNSRecord], answer_type: RecordSetKeys) -> None:
        """Add part of the QU response."""
        for record in target:
            if self._is_probe:
                self._ucast[answer_type].add(record)
            if not self._has_mcast_within_one_quarter_ttl(record):
                self._mcast[answer_type].add(record)
            elif not self._is_probe:
                self._ucast[answer_type].add(record)

    def add_ucast_question_response(self, answers: Set[DNSRecord], additionals: Set[DNSRecord]) -> None:
        """Generate a response to a unicast query."""
        self._ucast[RecordSetKeys.Answers].update(answers)
        self._ucast[RecordSetKeys.Additionals].update(additionals)

    def add_mcast_question_response(self, answers: Set[DNSRecord], additionals: Set[DNSRecord]) -> None:
        """Generate a response to a multicast query."""
        self._mcast[RecordSetKeys.Answers].update(answers)
        self._mcast[RecordSetKeys.Additionals].update(additionals)

    def outgoing_unicast(self) -> Optional[DNSOutgoing]:
        """Build the outgoing unicast response."""
        ucastout = self._construct_outgoing_from_record_set(self._ucast, False)
        # Adding the questions back when the source is
        # unicast (not MDNS port) is legacy behavior
        # Is this correct?
        if ucastout and self._ucast_source:
            for question in self._msg.questions:
                ucastout.add_question(question)
        return ucastout

    def outgoing_multicast(self) -> Optional[DNSOutgoing]:
        """Build the outgoing multicast response."""
        if not self._is_probe:
            self._suppress_mcasts_from_last_second(self._mcast[RecordSetKeys.Answers])
            self._suppress_mcasts_from_last_second(self._mcast[RecordSetKeys.Additionals])
        return self._construct_outgoing_from_record_set(self._mcast, True)

    def _construct_outgoing_from_record_set(
        self, rrset: _RecordSetType, multicast: bool
    ) -> Optional[DNSOutgoing]:
        """Add answers and additionals to a DNSOutgoing."""
        if not rrset[RecordSetKeys.Answers] and not rrset[RecordSetKeys.Additionals]:
            return None

        # Suppress any additionals that are already in answers
        rrset[RecordSetKeys.Additionals] -= rrset[RecordSetKeys.Answers]

        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA, multicast=multicast, id_=self._msg.id)
        for answer in rrset[RecordSetKeys.Answers]:
            out.add_answer_at_time(answer, 0)
        for additional in rrset[RecordSetKeys.Additionals]:
            out.add_additional_answer(additional)

        return out

    def _has_mcast_within_one_quarter_ttl(self, record: DNSRecord) -> bool:
        """Check to see if a record has been mcasted recently.

        https://datatracker.ietf.org/doc/html/rfc6762#section-5.4
        When receiving a question with the unicast-response bit set, a
        responder SHOULD usually respond with a unicast packet directed back
        to the querier.  However, if the responder has not multicast that
        record recently (within one quarter of its TTL), then the responder
        SHOULD instead multicast the response so as to keep all the peer
        caches up to date
        """
        maybe_entry = self._cache.get(record)
        return bool(maybe_entry and maybe_entry.get_expiration_time(_EXPIRE_REFRESH_TIME_PERCENT) > self._now)

    def _suppress_mcasts_from_last_second(self, records: Set[DNSRecord]) -> None:
        """Remove any records that were already sent in the last second."""
        records -= set(record for record in records if self._has_mcast_record_in_last_second(record))

    def _has_mcast_record_in_last_second(self, record: DNSRecord) -> bool:
        """Remove answers that were just broadcast

        Protect the network against excessive packet flooding
        https://datatracker.ietf.org/doc/html/rfc6762#section-14
        """
        maybe_entry = self._cache.get(record)
        return bool(maybe_entry and self._now - maybe_entry.created < 1000)


class QueryHandler:
    """Query the ServiceRegistry."""

    def __init__(self, registry: ServiceRegistry, cache: DNSCache) -> None:
        """Init the query handler."""
        self.registry = registry
        self.cache = cache

    def _answer_service_type_enumeration_query(
        self,
        msg: DNSIncoming,
    ) -> Set[DNSRecord]:
        """Provide an answer to a service type enumeration query.

        https://datatracker.ietf.org/doc/html/rfc6763#section-9
        """
        records: Set[DNSRecord] = set(
            DNSPointer(_SERVICE_TYPE_ENUMERATION_NAME, _TYPE_PTR, _CLASS_IN, _DNS_OTHER_TTL, stype)
            for stype in self.registry.get_types()
        )
        records -= set(dns_pointer for dns_pointer in records if dns_pointer.suppressed_by(msg))
        return records

    def _add_pointer_answers(
        self, name: str, msg: DNSIncoming, answers: Set[DNSRecord], additionals: Set[DNSRecord]
    ) -> None:
        """Answer PTR/ANY question."""
        for service in self.registry.get_infos_type(name):
            # Add recommended additional answers according to
            # https://tools.ietf.org/html/rfc6763#section-12.1.
            dns_pointer = service.dns_pointer()
            if not dns_pointer.suppressed_by(msg):
                answers.add(service.dns_pointer())
                additionals.add(service.dns_service())
                additionals.add(service.dns_text())
                additionals.update(service.dns_addresses())

    def _add_address_answers(self, name: str, msg: DNSIncoming, answers: Set[DNSRecord], type_: int) -> None:
        """Answer A/AAAA/ANY question."""
        for service in self.registry.get_infos_server(name):
            for dns_address in service.dns_addresses(version=_TYPE_TO_IP_VERSION[type_]):
                if not dns_address.suppressed_by(msg):
                    answers.add(dns_address)

    def _answer_question(
        self, msg: DNSIncoming, question: DNSQuestion
    ) -> Tuple[Set[DNSRecord], Set[DNSRecord]]:
        answers: Set[DNSRecord] = set()
        additionals: Set[DNSRecord] = set()
        type_ = question.type

        if type_ in (_TYPE_PTR, _TYPE_ANY):
            self._add_pointer_answers(question.name, msg, answers, additionals)

        if type_ in (_TYPE_A, _TYPE_AAAA, _TYPE_ANY):
            self._add_address_answers(question.name, msg, answers, type_)

        if type_ in (_TYPE_SRV, _TYPE_TXT, _TYPE_ANY):
            service = self.registry.get_info_name(question.name)  # type: ignore
            if service is not None:
                if type_ in (_TYPE_SRV, _TYPE_ANY):
                    dns_service = service.dns_service()
                    if not dns_service.suppressed_by(msg):
                        # Add recommended additional answers according to
                        # https://tools.ietf.org/html/rfc6763#section-12.2.
                        answers.add(service.dns_service())
                        additionals.update(service.dns_addresses())
                if type_ in (_TYPE_TXT, _TYPE_ANY):
                    dns_text = service.dns_text()
                    if not dns_text.suppressed_by(msg):
                        answers.add(service.dns_text())

        return answers, additionals

    def _answer_any_question(
        self, msg: DNSIncoming, question: DNSQuestion
    ) -> Tuple[Set[DNSRecord], Set[DNSRecord]]:
        if question.type == _TYPE_PTR and question.name.lower() == _SERVICE_TYPE_ENUMERATION_NAME:
            empty_additionals: Set[DNSRecord] = set()
            return self._answer_service_type_enumeration_query(msg), empty_additionals

        return self._answer_question(msg, question)

    def response(  # pylint: disable=unused-argument
        self, msg: DNSIncoming, addr: Optional[str], port: int
    ) -> Tuple[Optional[DNSOutgoing], Optional[DNSOutgoing]]:
        """Deal with incoming query packets. Provides a response if possible."""
        ucast_source = port != _MDNS_PORT
        query_res = _QueryResponse(self.cache, msg, ucast_source)

        for question in msg.questions:
            all_answers = self._answer_any_question(msg, question)
            if not ucast_source and question.unicast:
                query_res.add_qu_question_response(*all_answers)
            else:
                if ucast_source:
                    query_res.add_ucast_question_response(*all_answers)
                # We always multicast as well even if its a unicast
                # source as long as we haven't done it recently (75% of ttl)
                query_res.add_mcast_question_response(*all_answers)

        return query_res.outgoing_unicast(), query_res.outgoing_multicast()


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
