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

import asyncio
import ipaddress
import socket
from typing import Any, Dict, List, Optional, TYPE_CHECKING, Union, cast

from .._dns import DNSAddress, DNSPointer, DNSQuestionType, DNSRecord, DNSService, DNSText
from .._exceptions import BadTypeInNameException
from .._protocol import DNSOutgoing
from .._updates import RecordUpdate, RecordUpdateListener
from .._utils.asyncio import get_running_loop
from .._utils.name import service_type_name
from .._utils.net import (
    IPVersion,
    _encode_address,
    _is_v6_address,
)
from .._utils.struct import int2byte
from .._utils.time import current_time_millis, millis_to_seconds
from ..const import (
    _CLASS_IN,
    _CLASS_UNIQUE,
    _DNS_HOST_TTL,
    _DNS_OTHER_TTL,
    _FLAGS_QR_QUERY,
    _LISTENER_TIME,
    _LOADED_SYSTEM_TIMEOUT,
    _TYPE_A,
    _TYPE_AAAA,
    _TYPE_PTR,
    _TYPE_SRV,
    _TYPE_TXT,
)


if TYPE_CHECKING:
    # https://github.com/PyCQA/pylint/issues/3525
    from .._core import Zeroconf  # pylint: disable=cyclic-import


def instance_name_from_service_info(info: "ServiceInfo") -> str:
    """Calculate the instance name from the ServiceInfo."""
    # This is kind of funky because of the subtype based tests
    # need to make subtypes a first class citizen
    service_name = service_type_name(info.name)
    if not info.type.endswith(service_name):
        raise BadTypeInNameException
    return info.name[: -len(service_name) - 1]


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
    * interface_index: scope_id or zone_id for IPv6 link-local addresses i.e. an identifier of the interface
      where the peer is connected to
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
        parsed_addresses: Optional[List[str]] = None,
        interface_index: Optional[int] = None,
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
        self.interface_index = interface_index

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

    def parsed_scoped_addresses(self, version: IPVersion = IPVersion.All) -> List[str]:
        """Equivalent to parsed_addresses, with the exception that IPv6 Link-Local
        addresses are qualified with %<interface_index> when available
        """
        if self.interface_index is None:
            return self.parsed_addresses(version)

        def is_link_local(addr_str: str) -> Any:
            addr = ipaddress.ip_address(addr_str)
            return addr.version == 6 and addr.is_link_local

        ll_addrs = list(filter(is_link_local, self.parsed_addresses(version)))
        other_addrs = list(filter(lambda addr: not is_link_local(addr), self.parsed_addresses(version)))
        return ["{}%{}".format(addr, self.interface_index) for addr in ll_addrs] + other_addrs

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
            self._process_records_threadsafe(zc, now, [RecordUpdate(record, None)])

    def async_update_records(self, zc: 'Zeroconf', now: float, records: List[RecordUpdate]) -> None:
        """Updates service information from a DNS record.

        This method will be run in the event loop.
        """
        self._process_records_threadsafe(zc, now, records)

    def _process_records_threadsafe(self, zc: 'Zeroconf', now: float, records: List[RecordUpdate]) -> None:
        """Thread safe record updating."""
        update_addresses = False
        for record_update in records:
            if isinstance(record_update[0], DNSService):
                update_addresses = True
            self._process_record_threadsafe(record_update[0], now)

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
                if record.type is _TYPE_AAAA and ipaddress.IPv6Address(record.address).is_link_local:
                    self.interface_index = record.scope_id
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
                created=created,
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
        record_updates: List[RecordUpdate] = []
        cached_srv_record = zc.cache.get_by_details(self.name, _TYPE_SRV, _CLASS_IN)
        if cached_srv_record:
            # If there is a srv record, A and AAAA will already
            # be called and we do not want to do it twice
            record_updates.append(RecordUpdate(cached_srv_record, None))
        else:
            for record in self._get_address_records_from_cache(zc):
                record_updates.append(RecordUpdate(record, None))
        cached_txt_record = zc.cache.get_by_details(self.name, _TYPE_TXT, _CLASS_IN)
        if cached_txt_record:
            record_updates.append(RecordUpdate(cached_txt_record, None))
        self._process_records_threadsafe(zc, now, record_updates)
        return self._is_complete

    @property
    def _is_complete(self) -> bool:
        """The ServiceInfo has all expected properties."""
        return not (self.text is None or not self._addresses)

    def request(
        self, zc: 'Zeroconf', timeout: float, question_type: Optional[DNSQuestionType] = None
    ) -> bool:
        """Returns true if the service could be discovered on the
        network, and updates this object with details discovered.
        """
        assert zc.loop is not None and zc.loop.is_running()
        if zc.loop == get_running_loop():
            raise RuntimeError("Use AsyncServiceInfo.async_request from the event loop")
        return asyncio.run_coroutine_threadsafe(
            self.async_request(zc, timeout, question_type), zc.loop
        ).result(millis_to_seconds(timeout) + _LOADED_SYSTEM_TIMEOUT)

    async def async_request(
        self, zc: 'Zeroconf', timeout: float, question_type: Optional[DNSQuestionType] = None
    ) -> bool:
        """Returns true if the service could be discovered on the
        network, and updates this object with details discovered.
        """
        if self.load_from_cache(zc):
            return True

        first_request = True
        now = current_time_millis()
        delay = _LISTENER_TIME
        next_ = now
        last = now + timeout
        await zc.async_wait_for_start()
        try:
            zc.async_add_listener(self, None)
            while not self._is_complete:
                if last <= now:
                    return False
                if next_ <= now:
                    out = self.generate_request_query(
                        zc, now, question_type or DNSQuestionType.QU if first_request else DNSQuestionType.QM
                    )
                    first_request = False
                    if not out.questions:
                        return self.load_from_cache(zc)
                    zc.async_send(out)
                    next_ = now + delay
                    delay *= 2

                await zc.async_wait(min(next_, last) - now)
                now = current_time_millis()
        finally:
            zc.async_remove_listener(self)

        return True

    def generate_request_query(
        self, zc: 'Zeroconf', now: float, question_type: Optional[DNSQuestionType] = None
    ) -> DNSOutgoing:
        """Generate the request query."""
        out = DNSOutgoing(_FLAGS_QR_QUERY)
        out.add_question_or_one_cache(zc.cache, now, self.name, _TYPE_SRV, _CLASS_IN)
        out.add_question_or_one_cache(zc.cache, now, self.name, _TYPE_TXT, _CLASS_IN)
        out.add_question_or_all_cache(zc.cache, now, self.server, _TYPE_A, _CLASS_IN)
        out.add_question_or_all_cache(zc.cache, now, self.server, _TYPE_AAAA, _CLASS_IN)
        if question_type == DNSQuestionType.QU:
            for question in out.questions:
                question.unicast = True
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
                    'interface_index',
                )
            ),
        )
