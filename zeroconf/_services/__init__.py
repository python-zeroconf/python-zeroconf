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
import socket
import threading
import warnings
from collections import OrderedDict
from typing import Any, Callable, Dict, List, Optional, Set, TYPE_CHECKING, Tuple, Union, cast

from .._dns import DNSAddress, DNSPointer, DNSQuestion, DNSRecord, DNSService, DNSText
from .._exceptions import BadTypeInNameException
from .._protocol import DNSOutgoing
from .._utils.name import service_type_name
from .._utils.net import (
    IPVersion,
    _encode_address,
    _is_v6_address,
)
from .._utils.struct import int2byte
from .._utils.time import current_time_millis, millis_to_seconds
from ..const import (
    _BROWSER_BACKOFF_LIMIT,
    _BROWSER_TIME,
    _CLASS_IN,
    _CLASS_UNIQUE,
    _DNS_HOST_TTL,
    _DNS_OTHER_TTL,
    _DNS_PACKET_HEADER_LEN,
    _EXPIRE_REFRESH_TIME_PERCENT,
    _FLAGS_QR_QUERY,
    _LISTENER_TIME,
    _MAX_MSG_TYPICAL,
    _MDNS_ADDR,
    _MDNS_ADDR6,
    _MDNS_PORT,
    _TYPE_A,
    _TYPE_AAAA,
    _TYPE_PTR,
    _TYPE_SRV,
    _TYPE_TXT,
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


def instance_name_from_service_info(info: "ServiceInfo") -> str:
    """Calculate the instance name from the ServiceInfo."""
    # This is kind of funky because of the subtype based tests
    # need to make subtypes a first class citizen
    service_name = service_type_name(info.name)
    if not info.type.endswith(service_name):
        raise BadTypeInNameException
    return info.name[: -len(service_name) - 1]


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
        self._services: Dict[str, Dict[str, DNSPointer]] = {check_type_: {} for check_type_ in self.types}
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
                else:
                    raise NotImplementedError(state_change)

            handlers.append(on_change)

        for h in handlers:
            self.service_state_changed.register_handler(h)

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
            service_key = record.alias.lower()
            services_by_type = self._services[record.name]
            old_record = services_by_type.get(service_key)
            if old_record is None:
                services_by_type[service_key] = record
                self._enqueue_callback(ServiceStateChange.Added, record.name, record.alias)
            elif expired:
                del services_by_type[service_key]
                self._enqueue_callback(ServiceStateChange.Removed, record.name, record.alias)
            else:
                old_record.reset_ttl(record)
                expires = record.get_expiration_time(_EXPIRE_REFRESH_TIME_PERCENT)
                if expires < self._next_time[record.name]:
                    self._next_time[record.name] = expires
            return

        # If its expired or already exists in the cache it cannot be updated.
        if expired or self.zc.cache.async_get_unique(record):
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

    def run(self) -> None:
        """Run the browser."""
        questions = [DNSQuestion(type_, _TYPE_PTR, _CLASS_IN) for type_ in self.types]
        self.zc.add_listener(self, questions)

    def generate_ready_queries(self) -> List[DNSOutgoing]:
        """Generate the service browser query for any type that is due."""
        now = current_time_millis()

        if min(self._next_time.values()) > now:
            return []

        questions_with_known_answers: _QuestionWithKnownAnswers = {}

        for type_, due in self._next_time.items():
            if due > now:
                continue
            questions_with_known_answers[DNSQuestion(type_, _TYPE_PTR, _CLASS_IN)] = set(
                record for record in self._services[type_].values() if not record.is_stale(now)
            )
            self._next_time[type_] = now + self._delay[type_]
            self._delay[type_] = min(_BROWSER_BACKOFF_LIMIT * 1000, self._delay[type_] * 2)

        return _group_ptr_queries_with_known_answers(now, self.multicast, questions_with_known_answers)

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
        super().run()
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


class ServiceInfo(RecordUpdateListener):
    """Service information.

    Constructor parameters are as follows:

    * `type_`: fully qualified service type name
    * `name`: fully qualified service name
    * `port`: port that the service runs on
    * `weight`: weight of the service
    * `priority`: priority of the service
    * `properties`: dictionary of properties (or a bytes object holding the contents of the `text` field).
      converted to str and then encoded to bytes using UTF-8. Keys with `None` values are converted to
      value-less attributes.
    * `server`: fully qualified name for service host (defaults to name)
    * `host_ttl`: ttl used for A/SRV records
    * `other_ttl`: ttl used for PTR/TXT records
    * `addresses` and `parsed_addresses`: List of IP addresses (either as bytes, network byte order,
      or in parsed form as text; at most one of those parameters can be provided)

    """

    text = b''

    def __init__(
        self,
        type_: str,
        name: str,
        port: Optional[int] = None,
        weight: int = 0,
        priority: int = 0,
        properties: Union[bytes, Dict] = b'',
        server: Optional[str] = None,
        host_ttl: int = _DNS_HOST_TTL,
        other_ttl: int = _DNS_OTHER_TTL,
        *,
        addresses: Optional[List[bytes]] = None,
        parsed_addresses: Optional[List[str]] = None
    ) -> None:
        # Accept both none, or one, but not both.
        if addresses is not None and parsed_addresses is not None:
            raise TypeError("addresses and parsed_addresses cannot be provided together")
        if not type_.endswith(service_type_name(name, strict=False)):
            raise BadTypeInNameException
        self.type = type_
        self._name = name
        self.key = name.lower()
        if addresses is not None:
            self._addresses = addresses
        elif parsed_addresses is not None:
            self._addresses = [_encode_address(a) for a in parsed_addresses]
        else:
            self._addresses = []
        # This results in an ugly error when registering, better check now
        invalid = [a for a in self._addresses if not isinstance(a, bytes) or len(a) not in (4, 16)]
        if invalid:
            raise TypeError(
                'Addresses must be bytes, got %s. Hint: convert string addresses '
                'with socket.inet_pton' % invalid
            )
        self.port = port
        self.weight = weight
        self.priority = priority
        self.server = server if server else name
        self.server_key = self.server.lower()
        self._properties: Dict[Union[str, bytes], Optional[Union[str, bytes]]] = {}
        if isinstance(properties, bytes):
            self._set_text(properties)
        else:
            self._set_properties(properties)
        self.host_ttl = host_ttl
        self.other_ttl = other_ttl

    @property
    def name(self) -> str:
        """The name of the service."""
        return self._name

    @name.setter
    def name(self, name: str) -> None:
        """Replace the the name and reset the key."""
        self._name = name
        self.key = name.lower()

    @property
    def addresses(self) -> List[bytes]:
        """IPv4 addresses of this service.

        Only IPv4 addresses are returned for backward compatibility.
        Use :meth:`addresses_by_version` or :meth:`parsed_addresses` to
        include IPv6 addresses as well.
        """
        return self.addresses_by_version(IPVersion.V4Only)

    @addresses.setter
    def addresses(self, value: List[bytes]) -> None:
        """Replace the addresses list.

        This replaces all currently stored addresses, both IPv4 and IPv6.
        """
        self._addresses = value

    @property
    def properties(self) -> Dict:
        """If properties were set in the constructor this property returns the original dictionary
        of type `Dict[Union[bytes, str], Any]`.

        If properties are coming from the network, after decoding a TXT record, the keys are always
        bytes and the values are either bytes, if there was a value, even empty, or `None`, if there
        was none. No further decoding is attempted. The type returned is `Dict[bytes, Optional[bytes]]`.
        """
        return self._properties

    def addresses_by_version(self, version: IPVersion) -> List[bytes]:
        """List addresses matching IP version."""
        if version == IPVersion.V4Only:
            return [addr for addr in self._addresses if not _is_v6_address(addr)]
        if version == IPVersion.V6Only:
            return list(filter(_is_v6_address, self._addresses))
        return self._addresses

    def parsed_addresses(self, version: IPVersion = IPVersion.All) -> List[str]:
        """List addresses in their parsed string form."""
        result = self.addresses_by_version(version)
        return [
            socket.inet_ntop(socket.AF_INET6 if _is_v6_address(addr) else socket.AF_INET, addr)
            for addr in result
        ]

    def _set_properties(self, properties: Dict) -> None:
        """Sets properties and text of this info from a dictionary"""
        self._properties = properties
        list_ = []
        result = b''
        for key, value in properties.items():
            if isinstance(key, str):
                key = key.encode('utf-8')

            record = key
            if value is not None:
                if not isinstance(value, bytes):
                    value = str(value).encode('utf-8')
                record += b'=' + value
            list_.append(record)
        for item in list_:
            result = b''.join((result, int2byte(len(item)), item))
        self.text = result

    def _set_text(self, text: bytes) -> None:
        """Sets properties and text given a text field"""
        self.text = text
        end = len(text)
        if end == 0:
            self._properties = {}
            return
        result: Dict[Union[str, bytes], Optional[Union[str, bytes]]] = {}
        index = 0
        strs = []
        while index < end:
            length = text[index]
            index += 1
            strs.append(text[index : index + length])
            index += length

        key: bytes
        value: Optional[bytes]
        for s in strs:
            try:
                key, value = s.split(b'=', 1)
            except ValueError:
                # No equals sign at all
                key = s
                value = None

            # Only update non-existent properties
            if key and result.get(key) is None:
                result[key] = value

        self._properties = result

    def get_name(self) -> str:
        """Name accessor"""
        return self.name[: len(self.name) - len(self.type) - 1]

    def update_record(self, zc: 'Zeroconf', now: float, record: Optional[DNSRecord]) -> None:
        """Updates service information from a DNS record.

        This method is deprecated and will be removed in a future version.
        update_records should be implemented instead.

        This method will be run in the event loop.
        """
        if record is not None:
            self._process_records_threadsafe(zc, now, [record])

    def async_update_records(self, zc: 'Zeroconf', now: float, records: List[DNSRecord]) -> None:
        """Updates service information from a DNS record.

        This method will be run in the event loop.
        """
        self._process_records_threadsafe(zc, now, records)

    def _process_records_threadsafe(self, zc: 'Zeroconf', now: float, records: List[DNSRecord]) -> None:
        """Thread safe record updating."""
        update_addresses = False
        for record in records:
            if isinstance(record, DNSService):
                update_addresses = True
            self._process_record_threadsafe(record, now)

        # Only update addresses if the DNSService (.server) has changed
        if not update_addresses:
            return

        for record in self._get_address_records_from_cache(zc):
            self._process_record_threadsafe(record, now)

    def _process_record_threadsafe(self, record: DNSRecord, now: float) -> None:
        if record.is_expired(now):
            return

        if isinstance(record, DNSAddress):
            if record.key == self.server_key and record.address not in self._addresses:
                self._addresses.append(record.address)
            return

        if isinstance(record, DNSService):
            if record.key != self.key:
                return
            self.name = record.name
            self.server = record.server
            self.server_key = record.server.lower()
            self.port = record.port
            self.weight = record.weight
            self.priority = record.priority
            return

        if isinstance(record, DNSText):
            if record.key == self.key:
                self._set_text(record.text)

    def dns_addresses(
        self,
        override_ttl: Optional[int] = None,
        version: IPVersion = IPVersion.All,
        created: Optional[float] = None,
    ) -> List[DNSAddress]:
        """Return matching DNSAddress from ServiceInfo."""
        return [
            DNSAddress(
                self.server,
                _TYPE_AAAA if _is_v6_address(address) else _TYPE_A,
                _CLASS_IN | _CLASS_UNIQUE,
                override_ttl if override_ttl is not None else self.host_ttl,
                address,
                created,
            )
            for address in self.addresses_by_version(version)
        ]

    def dns_pointer(self, override_ttl: Optional[int] = None, created: Optional[float] = None) -> DNSPointer:
        """Return DNSPointer from ServiceInfo."""
        return DNSPointer(
            self.type,
            _TYPE_PTR,
            _CLASS_IN,
            override_ttl if override_ttl is not None else self.other_ttl,
            self.name,
            created,
        )

    def dns_service(self, override_ttl: Optional[int] = None, created: Optional[float] = None) -> DNSService:
        """Return DNSService from ServiceInfo."""
        return DNSService(
            self.name,
            _TYPE_SRV,
            _CLASS_IN | _CLASS_UNIQUE,
            override_ttl if override_ttl is not None else self.host_ttl,
            self.priority,
            self.weight,
            cast(int, self.port),
            self.server,
            created,
        )

    def dns_text(self, override_ttl: Optional[int] = None, created: Optional[float] = None) -> DNSText:
        """Return DNSText from ServiceInfo."""
        return DNSText(
            self.name,
            _TYPE_TXT,
            _CLASS_IN | _CLASS_UNIQUE,
            override_ttl if override_ttl is not None else self.other_ttl,
            self.text,
            created,
        )

    def _get_address_records_from_cache(self, zc: 'Zeroconf') -> List[DNSRecord]:
        """Get the address records from the cache."""
        return [
            *zc.cache.get_all_by_details(self.server, _TYPE_A, _CLASS_IN),
            *zc.cache.get_all_by_details(self.server, _TYPE_AAAA, _CLASS_IN),
        ]

    def load_from_cache(self, zc: 'Zeroconf') -> bool:
        """Populate the service info from the cache.

        This method is designed to be threadsafe.
        """
        now = current_time_millis()
        record_updates = []
        cached_srv_record = zc.cache.get_by_details(self.name, _TYPE_SRV, _CLASS_IN)
        if cached_srv_record:
            # If there is a srv record, A and AAAA will already
            # be called and we do not want to do it twice
            record_updates.append(cached_srv_record)
        else:
            record_updates.extend(self._get_address_records_from_cache(zc))
        cached_txt_record = zc.cache.get_by_details(self.name, _TYPE_TXT, _CLASS_IN)
        if cached_txt_record:
            record_updates.append(cached_txt_record)
        self._process_records_threadsafe(zc, now, record_updates)
        return self._is_complete

    @property
    def _is_complete(self) -> bool:
        """The ServiceInfo has all expected properties."""
        return not (self.text is None or not self._addresses)

    def request(self, zc: 'Zeroconf', timeout: float) -> bool:
        """Returns true if the service could be discovered on the
        network, and updates this object with details discovered.
        """
        if self.load_from_cache(zc):
            return True

        now = current_time_millis()
        delay = _LISTENER_TIME
        next_ = now
        last = now + timeout
        try:
            # Do not set a question on the listener to preload from cache
            # since we just checked it above in load_from_cache
            zc.add_listener(self, None)
            while not self._is_complete:
                if last <= now:
                    return False
                if next_ <= now:
                    out = self.generate_request_query(zc, now)
                    if not out.questions:
                        return True
                    zc.send(out)
                    next_ = now + delay
                    delay *= 2

                zc.wait(min(next_, last) - now)
                now = current_time_millis()
        finally:
            zc.remove_listener(self)

        return True

    def generate_request_query(self, zc: 'Zeroconf', now: float) -> DNSOutgoing:
        """Generate the request query."""
        out = DNSOutgoing(_FLAGS_QR_QUERY)
        out.add_question_or_one_cache(zc.cache, now, self.name, _TYPE_SRV, _CLASS_IN)
        out.add_question_or_one_cache(zc.cache, now, self.name, _TYPE_TXT, _CLASS_IN)
        out.add_question_or_all_cache(zc.cache, now, self.server, _TYPE_A, _CLASS_IN)
        out.add_question_or_all_cache(zc.cache, now, self.server, _TYPE_AAAA, _CLASS_IN)
        return out

    def __eq__(self, other: object) -> bool:
        """Tests equality of service name"""
        return isinstance(other, ServiceInfo) and other.name == self.name

    def __repr__(self) -> str:
        """String representation"""
        return '%s(%s)' % (
            type(self).__name__,
            ', '.join(
                '%s=%r' % (name, getattr(self, name))
                for name in (
                    'type',
                    'name',
                    'addresses',
                    'port',
                    'weight',
                    'priority',
                    'server',
                    'properties',
                )
            ),
        )
