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
import threading
import warnings
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Set, TYPE_CHECKING, Tuple, Union, cast

from .._cache import _UniqueRecordsType
from .._dns import DNSAddress, DNSPointer, DNSQuestion, DNSRecord
from .._protocol import DNSOutgoing
from .._utils.name import service_type_name
from .._utils.time import current_time_millis, millis_to_seconds
from ..const import (
    _BROWSER_BACKOFF_LIMIT,
    _BROWSER_TIME,
    _CLASS_IN,
    _DNS_PACKET_HEADER_LEN,
    _EXPIRE_REFRESH_TIME_PERCENT,
    _FLAGS_QR_QUERY,
    _MAX_MSG_TYPICAL,
    _MDNS_ADDR,
    _MDNS_ADDR6,
    _MDNS_PORT,
    _TYPE_PTR,
)


if TYPE_CHECKING:
    # https://github.com/PyCQA/pylint/issues/3525
    from .._core import Zeroconf  # pylint: disable=cyclic-import


_QuestionWithKnownAnswers = Dict[DNSQuestion, Set[DNSPointer]]


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


class _DNSPointerOutgoingBucket:
    """A DNSOutgoing bucket."""

    def __init__(self, now: float, multicast: bool) -> None:
        """Create a bucke to wrap a DNSOutgoing."""
        self.now = now
        self.out = DNSOutgoing(_FLAGS_QR_QUERY, multicast=multicast)
        self.bytes = 0

    def add(self, max_compressed_size: int, question: DNSQuestion, answers: Set[DNSPointer]) -> None:
        """Add a new set of questions and known answers to the outgoing."""
        self.out.add_question(question)
        for answer in answers:
            self.out.add_answer_at_time(answer, self.now)
        self.bytes += max_compressed_size


def _group_ptr_queries_with_known_answers(
    now: float, multicast: bool, question_with_known_answers: _QuestionWithKnownAnswers
) -> List[DNSOutgoing]:
    """Aggregate queries so that as many known answers as possible fit in the same packet
    without having known answers spill over into the next packet unless the
    question and known answers are always going to exceed the packet size.

    Some responders do not implement multi-packet known answer suppression
    so we try to keep all the known answers in the same packet as the
    questions.
    """
    # This is the maximum size the query + known answers can be with name compression.
    # The actual size of the query + known answers may be a bit smaller since other
    # parts may be shared when the final DNSOutgoing packets are constructed. The
    # goal of this algorithm is to quickly bucket the query + known answers without
    # the overhead of actually constructing the packets.
    query_by_size: Dict[DNSQuestion, int] = {
        question: (question.max_size + sum([answer.max_size_compressed for answer in known_answers]))
        for question, known_answers in question_with_known_answers.items()
    }
    max_bucket_size = _MAX_MSG_TYPICAL - _DNS_PACKET_HEADER_LEN
    query_buckets: List[_DNSPointerOutgoingBucket] = []
    for question in sorted(
        query_by_size,
        key=query_by_size.get,  # type: ignore
        reverse=True,
    ):
        max_compressed_size = query_by_size[question]
        answers = question_with_known_answers[question]
        for query_bucket in query_buckets:
            if query_bucket.bytes + max_compressed_size <= max_bucket_size:
                query_bucket.add(max_compressed_size, question, answers)
                break
        else:
            # If a single question and known answers won't fit in a packet
            # we will end up generating multiple packets, but there will never
            # be multiple questions
            query_bucket = _DNSPointerOutgoingBucket(now, multicast)
            query_bucket.add(max_compressed_size, question, answers)
            query_buckets.append(query_bucket)

    return [query_bucket.out for query_bucket in query_buckets]


def generate_service_query(
    zc: 'Zeroconf', now: float, types_: List[str], multicast: bool = True
) -> List[DNSOutgoing]:
    """Generate a service query for sending with zeroconf.send."""
    questions_with_known_answers: _QuestionWithKnownAnswers = {}
    for type_ in types_:
        question = DNSQuestion(type_, _TYPE_PTR, _CLASS_IN)
        questions_with_known_answers[question] = set(
            cast(DNSPointer, record)
            for record in zc.cache.get_all_by_details(type_, _TYPE_PTR, _CLASS_IN)
            if not record.is_stale(now)
        )
    return _group_ptr_queries_with_known_answers(now, multicast, questions_with_known_answers)


def _service_state_changed_from_listener(listener: ServiceListener) -> Callable[..., None]:
    """Generate a service_state_changed handlers from a listener."""

    def on_change(
        zeroconf: 'Zeroconf', service_type: str, name: str, state_change: ServiceStateChange
    ) -> None:
        assert listener is not None
        args = (zeroconf, service_type, name)
        if state_change is ServiceStateChange.Added:
            listener.add_service(*args)
        elif state_change is ServiceStateChange.Removed:
            listener.remove_service(*args)
        elif state_change is ServiceStateChange.Updated:
            if hasattr(listener, 'update_service'):
                listener.update_service(*args)
            else:
                warnings.warn(
                    "%r has no update_service method. Provide one (it can be empty if you "
                    "don't care about the updates), it'll become mandatory." % (listener,),
                    FutureWarning,
                )

    return on_change


class _ServiceBrowserBase(RecordUpdateListener):
    """Base class for ServiceBrowser."""

    def __init__(
        self,
        zc: 'Zeroconf',
        type_: Union[str, list],
        handlers: Optional[Union['ServiceListener', List[Callable[..., None]]]] = None,
        listener: Optional['ServiceListener'] = None,
        addr: Optional[str] = None,
        port: int = _MDNS_PORT,
        delay: int = _BROWSER_TIME,
    ) -> None:
        """Creates a browser for a specific type"""
        assert handlers or listener, 'You need to specify at least one handler'
        self.types: Set[str] = set(type_ if isinstance(type_, list) else [type_])
        for check_type_ in self.types:
            # Will generate BadTypeInNameException on a bad name
            service_type_name(check_type_, strict=False)
        self.zc = zc
        self.addr = addr
        self.port = port
        self.multicast = self.addr in (None, _MDNS_ADDR, _MDNS_ADDR6)
        current_time = current_time_millis()
        self._next_time = {check_type_: current_time for check_type_ in self.types}
        self._delay = {check_type_: delay for check_type_ in self.types}
        self._pending_handlers: OrderedDict[Tuple[str, str], ServiceStateChange] = OrderedDict()
        self._handlers_to_call: OrderedDict[Tuple[str, str], ServiceStateChange] = OrderedDict()
        self._service_state_changed = Signal()

        self.done = False

        if hasattr(handlers, 'add_service'):
            listener = cast('ServiceListener', handlers)
            handlers = None

        handlers = cast(List[Callable[..., None]], handlers or [])

        if listener:
            handlers.append(_service_state_changed_from_listener(listener))

        for h in handlers:
            self.service_state_changed.register_handler(h)

        self.zc.add_listener(self, [DNSQuestion(type_, _TYPE_PTR, _CLASS_IN) for type_ in self.types])

    @property
    def service_state_changed(self) -> SignalRegistrationInterface:
        return self._service_state_changed.registration_interface

    def _record_matching_type(self, record: DNSRecord) -> Optional[str]:
        """Return the type if the record matches one of the types we are browsing."""
        return next((type_ for type_ in self.types if record.name.endswith(type_)), None)

    def _enqueue_callback(
        self,
        state_change: ServiceStateChange,
        type_: str,
        name: str,
    ) -> None:
        # Code to ensure we only do a single update message
        # Precedence is; Added, Remove, Update
        key = (name, type_)
        if (
            state_change is ServiceStateChange.Added
            or (
                state_change is ServiceStateChange.Removed
                and self._pending_handlers.get(key) != ServiceStateChange.Added
            )
            or (state_change is ServiceStateChange.Updated and key not in self._pending_handlers)
        ):
            self._pending_handlers[key] = state_change

    def _async_process_record_update(self, now: float, record: DNSRecord) -> None:
        """Process a single record update from a batch of updates."""
        expired = record.is_expired(now)

        if isinstance(record, DNSPointer):
            if record.name not in self.types:
                return
            old_record = self.zc.cache.async_get_unique(
                DNSPointer(record.name, _TYPE_PTR, _CLASS_IN, 0, record.alias)
            )
            if old_record is None:
                self._enqueue_callback(ServiceStateChange.Added, record.name, record.alias)
            elif expired:
                self._enqueue_callback(ServiceStateChange.Removed, record.name, record.alias)
            else:
                expires = record.get_expiration_time(_EXPIRE_REFRESH_TIME_PERCENT)
                if expires < self._next_time[record.name]:
                    self._next_time[record.name] = expires
            return

        # If its expired or already exists in the cache it cannot be updated.
        if expired or self.zc.cache.async_get_unique(cast(_UniqueRecordsType, record)):
            return

        if isinstance(record, DNSAddress):
            # Iterate through the DNSCache and callback any services that use this address
            for service in self.zc.cache.async_entries_with_server(record.name):
                type_ = self._record_matching_type(service)
                if type_:
                    self._enqueue_callback(ServiceStateChange.Updated, type_, service.name)
                    break

            return

        type_ = self._record_matching_type(record)
        if type_:
            self._enqueue_callback(ServiceStateChange.Updated, type_, record.name)

    def async_update_records(self, zc: 'Zeroconf', now: float, records: List[DNSRecord]) -> None:
        """Callback invoked by Zeroconf when new information arrives.

        Updates information required by browser in the Zeroconf cache.

        Ensures that there is are no unecessary duplicates in the list.

        This method will be run in the event loop.
        """
        for record in records:
            self._async_process_record_update(now, record)

    def async_update_records_complete(self) -> None:
        """Called when a record update has completed for all handlers.

        At this point the cache will have the new records.

        This method will be run in the event loop.
        """
        # Cannot use .update here since can fail with
        # RuntimeError: dictionary changed size during iteration
        # for threaded ServiceBrowsers
        while self._pending_handlers:
            try:
                (name_type, state_change) = self._pending_handlers.popitem(False)
            except KeyError:
                return
            self._handlers_to_call[name_type] = state_change

    def cancel(self) -> None:
        """Cancel the browser."""
        self.done = True
        self.zc.remove_listener(self)

    def generate_ready_queries(self) -> List[DNSOutgoing]:
        """Generate the service browser query for any type that is due."""
        now = current_time_millis()

        if min(self._next_time.values()) > now:
            return []

        ready_types = []

        for type_, due in self._next_time.items():
            if due > now:
                continue

            ready_types.append(type_)
            self._next_time[type_] = now + self._delay[type_]
            self._delay[type_] = min(_BROWSER_BACKOFF_LIMIT * 1000, self._delay[type_] * 2)

        return generate_service_query(self.zc, now, ready_types, self.multicast)

    def _seconds_to_wait(self) -> Optional[float]:
        """Returns the number of seconds to wait for the next event."""
        # If there are handlers to call
        # we want to process them right away
        if self._handlers_to_call:
            return None

        # Wait for the type has the smallest next time
        next_time = min(self._next_time.values())
        now = current_time_millis()

        if next_time <= now:
            return None

        return millis_to_seconds(next_time - now)


class ServiceBrowser(_ServiceBrowserBase, threading.Thread):
    """Used to browse for a service of a specific type.

    The listener object will have its add_service() and
    remove_service() methods called when this browser
    discovers changes in the services availability."""

    def __init__(
        self,
        zc: 'Zeroconf',
        type_: Union[str, list],
        handlers: Optional[Union['ServiceListener', List[Callable[..., None]]]] = None,
        listener: Optional['ServiceListener'] = None,
        addr: Optional[str] = None,
        port: int = _MDNS_PORT,
        delay: int = _BROWSER_TIME,
    ) -> None:
        threading.Thread.__init__(self)
        super().__init__(zc, type_, handlers=handlers, listener=listener, addr=addr, port=port, delay=delay)
        self.daemon = True
        self.start()
        self.name = "zeroconf-ServiceBrowser-%s-%s" % (
            '-'.join([type_[:-7] for type_ in self.types]),
            getattr(self, 'native_id', self.ident),
        )

    def cancel(self) -> None:
        """Cancel the browser."""
        super().cancel()
        self.join()

    def run(self) -> None:
        """Run the browser thread."""
        while True:
            timeout = self._seconds_to_wait()
            if timeout:
                with self.zc.condition:
                    # We must check again while holding the condition
                    # in case the other thread has added to _handlers_to_call
                    # between when we checked above when we were not
                    # holding the condition
                    if not self._handlers_to_call:
                        self.zc.condition.wait(timeout)

            if self.zc.done or self.done:
                return

            outs = self.generate_ready_queries()
            for out in outs:
                self.zc.send(out, addr=self.addr, port=self.port)

            if not self._handlers_to_call:
                continue

            (name_type, state_change) = self._handlers_to_call.popitem(False)
            self._service_state_changed.fire(
                zeroconf=self.zc,
                service_type=name_type[1],
                name=name_type[0],
                state_change=state_change,
            )
