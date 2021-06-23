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
from typing import Dict, Iterable, List, Optional, Set, TYPE_CHECKING, Tuple, Union, cast

from ._cache import DNSCache, _UniqueRecordsType
from ._dns import DNSAddress, DNSPointer, DNSQuestion, DNSRRSet, DNSRecord
from ._history import QuestionHistory
from ._logger import log
from ._protocol import DNSIncoming, DNSOutgoing
from ._services.registry import ServiceRegistry
from ._updates import RecordUpdate, RecordUpdateListener
from ._utils.time import current_time_millis
from .const import (
    _CLASS_IN,
    _DNS_OTHER_TTL,
    _DNS_PTR_MIN_TTL,
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

if TYPE_CHECKING:
    # https://github.com/PyCQA/pylint/issues/3525
    from ._core import Zeroconf  # pylint: disable=cyclic-import


_AnswerWithAdditionalsType = Dict[DNSRecord, Set[DNSRecord]]


def sanitize_incoming_record(record: DNSRecord) -> None:
    """Protect zeroconf from records that can cause denial of service.

    We enforce a minimum TTL for PTR records to avoid
    ServiceBrowsers generating excessive queries refresh queries.
    Apple uses a 15s minimum TTL, however we do not have the same
    level of rate limit and safe guards so we use 1/4 of the recommended value.
    """
    if record.ttl and record.ttl < _DNS_PTR_MIN_TTL and isinstance(record, DNSPointer):
        log.debug(
            "Increasing effective ttl of %s to minimum of %s to protect against excessive refreshes.",
            record,
            _DNS_PTR_MIN_TTL,
        )
        record.set_created_ttl(record.created, _DNS_PTR_MIN_TTL)


class _QueryResponse:
    """A pair for unicast and multicast DNSOutgoing responses."""

    def __init__(self, cache: DNSCache, msg: DNSIncoming, ucast_source: bool) -> None:
        """Build a query response."""
        self._msg = msg
        self._is_probe = msg.num_authorities > 0
        self._ucast_source = ucast_source
        self._now = current_time_millis()
        self._cache = cache
        self._additionals: _AnswerWithAdditionalsType = {}
        self._ucast: Set[DNSRecord] = set()
        self._mcast: Set[DNSRecord] = set()

    def add_qu_question_response(self, answers: _AnswerWithAdditionalsType) -> None:
        """Generate a response to a multicast QU query."""
        for record, additionals in answers.items():
            self._additionals[record] = additionals
            if self._is_probe:
                self._ucast.add(record)
            if not self._has_mcast_within_one_quarter_ttl(record):
                self._mcast.add(record)
            elif not self._is_probe:
                self._ucast.add(record)

    def add_ucast_question_response(self, answers: _AnswerWithAdditionalsType) -> None:
        """Generate a response to a unicast query."""
        self._additionals.update(answers)
        self._ucast.update(answers.keys())

    def add_mcast_question_response(self, answers: _AnswerWithAdditionalsType) -> None:
        """Generate a response to a multicast query."""
        self._additionals.update(answers)
        self._mcast.update(answers.keys())

    def outgoing_unicast(self) -> Optional[DNSOutgoing]:
        """Build the outgoing unicast response."""
        ucastout = self._construct_outgoing_from_record_set(self._ucast, False)
        # Adding the questions back when the source is legacy unicast behavior
        if ucastout and self._ucast_source:
            for question in self._msg.questions:
                ucastout.add_question(question)
        return ucastout

    def outgoing_multicast(self) -> Optional[DNSOutgoing]:
        """Build the outgoing multicast response."""
        if not self._is_probe:
            self._suppress_mcasts_from_last_second(self._mcast)
        return self._construct_outgoing_from_record_set(self._mcast, True)

    def _construct_outgoing_from_record_set(
        self, answers_rrset: Set[DNSRecord], multicast: bool
    ) -> Optional[DNSOutgoing]:
        """Add answers and additionals to a DNSOutgoing."""
        # Find additionals and suppress any additionals that are already in answers
        additionals_rrset = self._additionals_from_answers_rrset(answers_rrset) - answers_rrset
        if not answers_rrset:
            return None

        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA, multicast=multicast, id_=self._msg.id)
        for answer in answers_rrset:
            out.add_answer_at_time(answer, 0)
        for additional in additionals_rrset:
            out.add_additional_answer(additional)
        return out

    def _additionals_from_answers_rrset(self, rrset: Set[DNSRecord]) -> Set[DNSRecord]:
        additionals: Set[DNSRecord] = set()
        return additionals.union(*[self._additionals[record] for record in rrset])

    def _suppress_mcasts_from_last_second(self, rrset: Set[DNSRecord]) -> None:
        """Remove any records that were already sent in the last second."""
        rrset -= set(record for record in rrset if self._has_mcast_record_in_last_second(record))

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
        maybe_entry = self._cache.async_get_unique(cast(_UniqueRecordsType, record))
        return bool(maybe_entry and maybe_entry.is_recent(self._now))

    def _has_mcast_record_in_last_second(self, record: DNSRecord) -> bool:
        """Remove answers that were just broadcast
        Protect the network against excessive packet flooding
        https://datatracker.ietf.org/doc/html/rfc6762#section-14
        """
        maybe_entry = self._cache.async_get_unique(cast(_UniqueRecordsType, record))
        return bool(maybe_entry and self._now - maybe_entry.created < 1000)


class QueryHandler:
    """Query the ServiceRegistry."""

    def __init__(self, registry: ServiceRegistry, cache: DNSCache, question_history: QuestionHistory) -> None:
        """Init the query handler."""
        self.registry = registry
        self.cache = cache
        self.question_history = question_history

    def _add_service_type_enumeration_query_answers(
        self, answer_set: _AnswerWithAdditionalsType, known_answers: DNSRRSet, now: float
    ) -> None:
        """Provide an answer to a service type enumeration query.

        https://datatracker.ietf.org/doc/html/rfc6763#section-9
        """
        for stype in self.registry.get_types():
            dns_pointer = DNSPointer(
                _SERVICE_TYPE_ENUMERATION_NAME, _TYPE_PTR, _CLASS_IN, _DNS_OTHER_TTL, stype, now
            )
            if not known_answers.suppresses(dns_pointer):
                answer_set[dns_pointer] = set()

    def _add_pointer_answers(
        self, name: str, answer_set: _AnswerWithAdditionalsType, known_answers: DNSRRSet, now: float
    ) -> None:
        """Answer PTR/ANY question."""
        for service in self.registry.get_infos_type(name):
            # Add recommended additional answers according to
            # https://tools.ietf.org/html/rfc6763#section-12.1.
            dns_pointer = service.dns_pointer(created=now)
            if not known_answers.suppresses(dns_pointer):
                answer_set[dns_pointer] = set(
                    [
                        service.dns_service(created=now),
                        service.dns_text(created=now),
                        *service.dns_addresses(created=now),
                    ]
                )

    def _add_address_answers(
        self,
        name: str,
        answer_set: _AnswerWithAdditionalsType,
        known_answers: DNSRRSet,
        now: float,
        type_: int,
    ) -> None:
        """Answer A/AAAA/ANY question."""
        for service in self.registry.get_infos_server(name):
            answers: List[DNSAddress] = []
            additionals: Set[DNSRecord] = set()
            for dns_address in service.dns_addresses(created=now):
                if dns_address.type != type_:
                    additionals.add(dns_address)
                elif not known_answers.suppresses(dns_address):
                    answers.append(dns_address)
            for answer in answers:
                answer_set[answer] = additionals

    def _answer_question(
        self,
        question: DNSQuestion,
        answer_set: _AnswerWithAdditionalsType,
        known_answers: DNSRRSet,
        now: float,
    ) -> None:
        if question.type == _TYPE_PTR and question.name.lower() == _SERVICE_TYPE_ENUMERATION_NAME:
            self._add_service_type_enumeration_query_answers(answer_set, known_answers, now)
            return

        type_ = question.type

        if type_ in (_TYPE_PTR, _TYPE_ANY):
            self._add_pointer_answers(question.name, answer_set, known_answers, now)

        if type_ in (_TYPE_A, _TYPE_AAAA, _TYPE_ANY):
            self._add_address_answers(question.name, answer_set, known_answers, now, type_)

        if type_ in (_TYPE_SRV, _TYPE_TXT, _TYPE_ANY):
            service = self.registry.get_info_name(question.name)  # type: ignore
            if service is not None:
                if type_ in (_TYPE_SRV, _TYPE_ANY):
                    # Add recommended additional answers according to
                    # https://tools.ietf.org/html/rfc6763#section-12.2.
                    dns_service = service.dns_service(created=now)
                    if not known_answers.suppresses(dns_service):
                        answer_set[dns_service] = set(service.dns_addresses(created=now))
                if type_ in (_TYPE_TXT, _TYPE_ANY):
                    dns_text = service.dns_text(created=now)
                    if not known_answers.suppresses(dns_text):
                        answer_set[dns_text] = set()

    def async_response(  # pylint: disable=unused-argument
        self, msgs: List[DNSIncoming], addr: Optional[str], port: int
    ) -> Tuple[Optional[DNSOutgoing], Optional[DNSOutgoing]]:
        """Deal with incoming query packets. Provides a response if possible.

        This function must be run in the event loop as it is not
        threadsafe.
        """
        ucast_source = port != _MDNS_PORT
        known_answers = DNSRRSet(itertools.chain(*[msg.answers for msg in msgs]))
        query_res = _QueryResponse(self.cache, msgs[0], ucast_source)

        for msg in msgs:
            for question in msg.questions:
                if not question.unicast:
                    self.question_history.add_question_at_time(question, msg.now, set(known_answers.lookup))
                answer_set: _AnswerWithAdditionalsType = {}
                self._answer_question(question, answer_set, known_answers, msg.now)
                if not ucast_source and question.unicast:
                    query_res.add_qu_question_response(answer_set)
                    continue
                if ucast_source:
                    query_res.add_ucast_question_response(answer_set)
                # We always multicast as well even if its a unicast
                # source as long as we haven't done it recently (75% of ttl)
                query_res.add_mcast_question_response(answer_set)

        return query_res.outgoing_unicast(), query_res.outgoing_multicast()


class RecordManager:
    """Process records into the cache and notify listeners."""

    def __init__(self, zeroconf: 'Zeroconf') -> None:
        """Init the record manager."""
        self.zc = zeroconf
        self.cache = zeroconf.cache
        self.listeners: List[RecordUpdateListener] = []

    def async_updates(self, now: float, records: List[RecordUpdate]) -> None:
        """Used to notify listeners of new information that has updated
        a record.

        This method must be called before the cache is updated.

        This method will be run in the event loop.
        """
        for listener in self.listeners:
            listener.async_update_records(self.zc, now, records)

    def async_updates_complete(self) -> None:
        """Used to notify listeners of new information that has updated
        a record.

        This method must be called after the cache is updated.

        This method will be run in the event loop.
        """
        for listener in self.listeners:
            listener.async_update_records_complete()
        self.zc.async_notify_all()

    def async_updates_from_response(self, msg: DNSIncoming) -> None:
        """Deal with incoming response packets.  All answers
        are held in the cache, and listeners are notified.

        This function must be run in the event loop as it is not
        threadsafe.
        """
        updates: List[RecordUpdate] = []
        address_adds: List[DNSAddress] = []
        other_adds: List[DNSRecord] = []
        removes: List[DNSRecord] = []
        now = msg.now
        unique_types: Set[Tuple[str, int, int]] = set()

        for record in msg.answers:
            sanitize_incoming_record(record)

            if record.unique:  # https://tools.ietf.org/html/rfc6762#section-10.2
                unique_types.add((record.name, record.type, record.class_))

            maybe_entry = self.cache.async_get_unique(cast(_UniqueRecordsType, record))
            if not record.is_expired(now):
                if maybe_entry is not None:
                    maybe_entry.reset_ttl(record)
                else:
                    if isinstance(record, DNSAddress):
                        address_adds.append(record)
                    else:
                        other_adds.append(record)
                updates.append(RecordUpdate(record, maybe_entry))
            # This is likely a goodbye since the record is
            # expired and exists in the cache
            elif maybe_entry is not None:
                updates.append(RecordUpdate(record, maybe_entry))
                removes.append(record)

        if unique_types:
            self._async_mark_unique_cached_records_older_than_1s_to_expire(unique_types, msg.answers, now)

        if updates:
            self.async_updates(now, updates)
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
        if other_adds or address_adds:
            self.cache.async_add_records(itertools.chain(address_adds, other_adds))
        # Removes are processed last since
        # ServiceInfo could generate an un-needed query
        # because the data was not yet populated.
        if removes:
            self.cache.async_remove_records(removes)
        if updates:
            self.async_updates_complete()

    def _async_mark_unique_cached_records_older_than_1s_to_expire(
        self, unique_types: Set[Tuple[str, int, int]], answers: Iterable[DNSRecord], now: float
    ) -> None:
        # rfc6762#section-10.2 para 2
        # Since unique is set, all old records with that name, rrtype,
        # and rrclass that were received more than one second ago are declared
        # invalid, and marked to expire from the cache in one second.
        answers_rrset = DNSRRSet(answers)
        for name, type_, class_ in unique_types:
            for entry in self.cache.async_all_by_details(name, type_, class_):
                if (now - entry.created > 1000) and entry not in answers_rrset:
                    # Expire in 1s
                    entry.set_created_ttl(now, 1)

    def async_add_listener(
        self, listener: RecordUpdateListener, question: Optional[Union[DNSQuestion, List[DNSQuestion]]]
    ) -> None:
        """Adds a listener for a given question.  The listener will have
        its update_record method called when information is available to
        answer the question(s).

        This function is not threadsafe and must be called in the eventloop.
        """
        self.listeners.append(listener)

        if question is None:
            return

        questions = [question] if isinstance(question, DNSQuestion) else question
        assert self.zc.loop is not None
        self._async_update_matching_records(listener, questions)

    def _async_update_matching_records(
        self, listener: RecordUpdateListener, questions: List[DNSQuestion]
    ) -> None:
        """Calls back any existing entries in the cache that answer the question.

        This function must be run from the event loop.
        """
        now = current_time_millis()
        records: List[RecordUpdate] = []
        for question in questions:
            for record in self.cache.async_entries_with_name(question.name):
                if not record.is_expired(now) and question.answered_by(record):
                    records.append(RecordUpdate(record, None))

        if not records:
            return
        listener.async_update_records(self.zc, now, records)
        listener.async_update_records_complete()
        self.zc.async_notify_all()

    def async_remove_listener(self, listener: RecordUpdateListener) -> None:
        """Removes a listener.

        This function is not threadsafe and must be called in the eventloop.
        """
        try:
            self.listeners.remove(listener)
            self.zc.async_notify_all()
        except ValueError as e:
            log.exception('Failed to remove listener: %r', e)
