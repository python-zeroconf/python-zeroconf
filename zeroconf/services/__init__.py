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

from ..const import (
    _BROWSER_BACKOFF_LIMIT,
    _BROWSER_TIME,
    _CLASS_IN,
    _CLASS_UNIQUE,
    _DNS_HOST_TTL,
    _DNS_OTHER_TTL,
    _EXPIRE_REFRESH_TIME_PERCENT,
    _FLAGS_QR_QUERY,
    _LISTENER_TIME,
    _MDNS_ADDR,
    _MDNS_ADDR6,
    _MDNS_PORT,
    _TYPE_A,
    _TYPE_AAAA,
    _TYPE_PTR,
    _TYPE_SRV,
    _TYPE_TXT,
)
from ..dns import DNSAddress, DNSOutgoing, DNSPointer, DNSQuestion, DNSRecord, DNSService, DNSText
from ..exceptions import BadTypeInNameException
from ..utils.name import service_type_name
from ..utils.net import (
    IPVersion,
    _encode_address,
    _is_v6_address,
)
from ..utils.struct import int2byte
from ..utils.time import current_time_millis, millis_to_seconds

if TYPE_CHECKING:
    # https://github.com/PyCQA/pylint/issues/3525
    from ..core import Zeroconf  # pylint: disable=cyclic-import


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
        self._handlers = []  # type: List[Callable[..., None]]

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

    def update_records(self, zc: 'Zeroconf', now: float, records: List[DNSRecord]) -> None:
        """Update multiple records in one shot.

        All records that are received in a single packet are passed
        to update_records.

        This implementation is a compatiblity shim to ensure older code
        that uses RecordUpdateListener as a base class will continue to
        get calls to update_record. This method will raise
        NotImplementedError in a future version.

        At this point the cache will not have the new records
        """
        for record in records:
            self.update_record(zc, now, record)

    def update_records_complete(self) -> None:
        """Called when a record update has completed for all handlers.

        At this point the cache will have the new records.
        """


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
        self.types = set(type_ if isinstance(type_, list) else [type_])  # type: Set[str]
        for check_type_ in self.types:
            if not check_type_.endswith(service_type_name(check_type_, strict=False)):
                raise BadTypeInNameException
        self.zc = zc
        self.addr = addr
        self.port = port
        self.multicast = self.addr in (None, _MDNS_ADDR, _MDNS_ADDR6)
        self._services = {
            check_type_: {} for check_type_ in self.types
        }  # type: Dict[str, Dict[str, DNSRecord]]
        current_time = current_time_millis()
        self._next_time = {check_type_: current_time for check_type_ in self.types}
        self._delay = {check_type_: delay for check_type_ in self.types}
        self._pending_handlers = OrderedDict()  # type: OrderedDict[Tuple[str, str], ServiceStateChange]
        self._handlers_to_call = OrderedDict()  # type: OrderedDict[Tuple[str, str], ServiceStateChange]

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

    def _process_record_update(
        self,
        zc: 'Zeroconf',
        now: float,
        record: DNSRecord,
    ) -> None:
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
        if expired or self.zc.cache.get(record):
            return

        if isinstance(record, DNSAddress):
            # Only trigger an updated event if the address is new
            if record.address in set(
                service.address
                for service in zc.cache.entries_with_name(record.name)
                if isinstance(service, DNSAddress)
            ):
                return

            # Iterate through the DNSCache and callback any services that use this address
            for service in self.zc.cache.entries_with_server(record.name):
                type_ = self._record_matching_type(service)
                if type_:
                    self._enqueue_callback(ServiceStateChange.Updated, type_, service.name)
                    break

            return

        type_ = self._record_matching_type(record)
        if type_:
            self._enqueue_callback(ServiceStateChange.Updated, type_, record.name)

    def update_records(self, zc: 'Zeroconf', now: float, records: List[DNSRecord]) -> None:
        """Callback invoked by Zeroconf when new information arrives.

        Updates information required by browser in the Zeroconf cache.

        Ensures that there is are no unecessary duplicates in the list.
        """
        for record in records:
            self._process_record_update(zc, now, record)

    def update_records_complete(self) -> None:
        """Called when a record update has completed for all handlers.

        At this point the cache will have the new records.
        """
        self._handlers_to_call.update(self._pending_handlers)
        self._pending_handlers.clear()

    def cancel(self) -> None:
        """Cancel the browser."""
        self.done = True
        self.zc.remove_listener(self)

    def run(self) -> None:
        """Run the browser."""
        questions = [DNSQuestion(type_, _TYPE_PTR, _CLASS_IN) for type_ in self.types]
        self.zc.add_listener(self, questions)

    def generate_ready_queries(self) -> Optional[DNSOutgoing]:
        """Generate the service browser query for any type that is due."""
        out = None
        now = current_time_millis()

        if min(self._next_time.values()) > now:
            return out

        for type_, due in self._next_time.items():
            if due > now:
                continue

            if out is None:
                out = DNSOutgoing(_FLAGS_QR_QUERY, multicast=self.multicast)
            out.add_question(DNSQuestion(type_, _TYPE_PTR, _CLASS_IN))

            for record in self._services[type_].values():
                if not record.is_stale(now):
                    out.add_answer_at_time(record, now)

            self._next_time[type_] = now + self._delay[type_]
            self._delay[type_] = min(_BROWSER_BACKOFF_LIMIT * 1000, self._delay[type_] * 2)
        return out

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

            out = self.generate_ready_queries()
            if out:
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
        self.name = name
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
        if server:
            self.server = server
        else:
            self.server = name
        self.server_key = self.server.lower()
        self._properties = {}  # type: Dict
        self._set_properties(properties)
        self.host_ttl = host_ttl
        self.other_ttl = other_ttl

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

    def _set_properties(self, properties: Union[bytes, Dict]) -> None:
        """Sets properties and text of this info from a dictionary"""
        if isinstance(properties, dict):
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
        else:
            self.text = properties

    def _set_text(self, text: bytes) -> None:
        """Sets properties and text given a text field"""
        self.text = text
        result = {}  # type: Dict
        end = len(text)
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
        """
        if record is not None:
            self.update_records(zc, now, [record])

    def update_records(self, zc: 'Zeroconf', now: float, records: List[DNSRecord]) -> None:
        """Updates service information from a DNS record."""
        update_addresses = False
        for record in records:
            if isinstance(record, DNSService):
                update_addresses = True
            self._process_record(record, now)

        # Only update addresses if the DNSService (.server) has changed
        if not update_addresses:
            return

        for record in self._get_address_records_from_cache(zc):
            self._process_record(record, now)

    def _process_record(self, record: DNSRecord, now: float) -> None:
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

    def dns_addresses(self, override_ttl: Optional[int] = None) -> List[DNSAddress]:
        """Return matching DNSAddress from ServiceInfo."""
        return [
            DNSAddress(
                self.server,
                _TYPE_AAAA if _is_v6_address(address) else _TYPE_A,
                _CLASS_IN | _CLASS_UNIQUE,
                override_ttl if override_ttl is not None else self.host_ttl,
                address,
            )
            for address in self._addresses
        ]

    def dns_pointer(self, override_ttl: Optional[int] = None) -> DNSPointer:
        """Return DNSPointer from ServiceInfo."""
        return DNSPointer(
            self.type,
            _TYPE_PTR,
            _CLASS_IN,
            override_ttl if override_ttl is not None else self.other_ttl,
            self.name,
        )

    def dns_service(self, override_ttl: Optional[int] = None) -> DNSService:
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
        )

    def dns_text(self, override_ttl: Optional[int] = None) -> DNSText:
        """Return DNSText from ServiceInfo."""
        return DNSText(
            self.name,
            _TYPE_TXT,
            _CLASS_IN | _CLASS_UNIQUE,
            override_ttl if override_ttl is not None else self.other_ttl,
            self.text,
        )

    def _get_address_records_from_cache(self, zc: 'Zeroconf') -> List[DNSRecord]:
        """Get the address records from the cache."""
        address_records = []
        cached_a_record = zc.cache.get_by_details(self.server, _TYPE_A, _CLASS_IN)
        if cached_a_record:
            address_records.append(cached_a_record)
        address_records.extend(zc.cache.get_all_by_details(self.server, _TYPE_AAAA, _CLASS_IN))
        return address_records

    def load_from_cache(self, zc: 'Zeroconf') -> bool:
        """Populate the service info from the cache."""
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
        self.update_records(zc, now, record_updates)
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
        out.add_question_or_one_cache(zc.cache, now, self.server, _TYPE_A, _CLASS_IN)
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
