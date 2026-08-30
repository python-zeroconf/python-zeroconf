"""A pure python implementation of multicast DNS service discovery.

Licensed under LGPL-2.1-or-later; see COPYING for details. This file is
part of a continuously modified work; modification dates are recorded
in the project's git history.
"""

from __future__ import annotations

import asyncio
import random
import warnings
from collections.abc import Sequence
from typing import TYPE_CHECKING, cast

from .._cache import DNSCache
from .._dns import (
    DNSAddress,
    DNSNsec,
    DNSPointer,
    DNSQuestion,
    DNSQuestionType,
    DNSRecord,
    DNSService,
    DNSText,
)
from .._exceptions import BadTypeInNameException
from .._history import QuestionHistory
from .._logger import log
from .._protocol.outgoing import DNSOutgoing
from .._record_update import RecordUpdate
from .._updates import RecordUpdateListener
from .._utils.asyncio import (
    _resolve_all_futures_to_none,
    get_running_loop,
    run_coro_with_timeout,
    wait_for_future_set_or_timeout,
)
from .._utils.ipaddress import (
    ZeroconfIPv4Address,
    ZeroconfIPv6Address,
    cached_ip_addresses,
    get_ip_address_object_from_record,
    ip_bytes_and_scope_to_address,
    str_without_scope_id,
)
from .._utils.name import service_type_name
from .._utils.net import IPVersion, _encode_address
from .._utils.time import current_time_millis
from ..const import (
    _CLASS_IN,
    _CLASS_IN_UNIQUE,
    _DNS_HOST_TTL,
    _DNS_OTHER_TTL,
    _DUPLICATE_QUESTION_INTERVAL,
    _FLAGS_QR_QUERY,
    _LISTENER_TIME,
    _MDNS_PORT,
    _TYPE_A,
    _TYPE_AAAA,
    _TYPE_NSEC,
    _TYPE_PTR,
    _TYPE_SRV,
    _TYPE_TXT,
)

_IPVersion_All_value = IPVersion.All.value
_IPVersion_V4Only_value = IPVersion.V4Only.value
# https://datatracker.ietf.org/doc/html/rfc6762#section-5.2
# The most common case for calling ServiceInfo is from a
# ServiceBrowser. After the first request we add a few random
# milliseconds to the delay between requests to reduce the chance
# that there are multiple ServiceBrowser callbacks running on
# the network that are firing at the same time when they
# see the same multicast response and decide to refresh
# the A/AAAA/SRV records for a host.
_AVOID_SYNC_DELAY_RANDOM_INTERVAL = (20, 120)

_TYPE_AAAA_RECORDS = {_TYPE_AAAA}
_TYPE_A_RECORDS = {_TYPE_A}
_TYPE_A_AAAA_RECORDS = {_TYPE_A, _TYPE_AAAA}

bytes_ = bytes
float_ = float
int_ = int
str_ = str
RecordUpdate_ = RecordUpdate

QU_QUESTION = DNSQuestionType.QU
QM_QUESTION = DNSQuestionType.QM

randint = random.randint

if TYPE_CHECKING:
    from .._core import Zeroconf


def _index_of_same_address(
    addresses: Sequence[ZeroconfIPv4Address | ZeroconfIPv6Address],
    ip_addr: ZeroconfIPv4Address | ZeroconfIPv6Address,
) -> int:
    """Return the index of an existing entry with the same packed bytes, or -1.

    Match by ``zc_integer`` so IPv6 addresses that differ only in
    scope_id (one observed without scope on an IPv4 socket, another
    observed with scope on an IPv6 socket) collapse to a single entry.
    """
    target = ip_addr.zc_integer
    for idx, existing in enumerate(addresses):
        if existing.zc_integer == target:
            return idx
    return -1


def _has_more_scope_info(
    new_addr: ZeroconfIPv4Address | ZeroconfIPv6Address,
    existing: ZeroconfIPv4Address | ZeroconfIPv6Address,
) -> bool:
    """True if ``new_addr`` carries a scope_id the ``existing`` entry lacks."""
    if new_addr.version != 6:
        return False
    if TYPE_CHECKING:
        assert isinstance(new_addr, ZeroconfIPv6Address)
        assert isinstance(existing, ZeroconfIPv6Address)
    return new_addr.scope_id is not None and existing.scope_id is None


def instance_name_from_service_info(info: ServiceInfo, strict: bool = True) -> str:
    """Calculate the instance name from the ServiceInfo."""
    # This is kind of funky because of the subtype based tests
    # need to make subtypes a first class citizen
    service_name = service_type_name(info.name, strict=strict)
    if not info.type.endswith(service_name):
        raise BadTypeInNameException
    return info.name[: -len(service_name) - 1]


class ServiceInfo(RecordUpdateListener):
    """Everything known about a single service instance.

    Holds the instance name, its type, the host server name, port,
    addresses, priority, weight, and the properties dictionary carried
    by the TXT record (pass a dict, or bytes to reuse a raw TXT
    payload). Build one to register a service, or let request or
    async_request populate one from the network.
    """

    __slots__ = (
        "_decoded_properties",
        "_dns_address_cache",
        "_dns_address_nsec_cache",
        "_dns_pointer_cache",
        "_dns_service_cache",
        "_dns_text_cache",
        "_get_address_and_nsec_records_cache",
        "_ipv4_addresses",
        "_ipv4_denied",
        "_ipv6_addresses",
        "_ipv6_denied",
        "_name",
        "_new_records_futures",
        "_properties",
        "_query_record_types",
        "_txt_seen",
        "host_ttl",
        "interface_index",
        "key",
        "other_ttl",
        "port",
        "priority",
        "server",
        "server_key",
        "text",
        "type",
        "weight",
    )

    def __init__(
        self,
        type_: str,
        name: str,
        port: int | None = None,
        weight: int = 0,
        priority: int = 0,
        properties: bytes | dict | None = None,
        server: str | None = None,
        host_ttl: int = _DNS_HOST_TTL,
        other_ttl: int = _DNS_OTHER_TTL,
        *,
        addresses: Sequence[bytes | str] | None = None,
        parsed_addresses: list[str] | None = None,
        interface_index: int | None = None,
    ) -> None:
        # Accept both none, or one, but not both.
        if addresses is not None and parsed_addresses is not None:
            raise TypeError("addresses and parsed_addresses cannot be provided together")
        if not type_.endswith(service_type_name(name, strict=False)):
            raise BadTypeInNameException
        self.interface_index = interface_index
        self.text = b""
        self.type = type_
        self._name = name
        self.key = name.lower()
        self._ipv4_addresses: list[ZeroconfIPv4Address] = []
        self._ipv6_addresses: list[ZeroconfIPv6Address] = []
        self._ipv4_denied = False
        self._ipv6_denied = False
        if addresses is not None:
            self.addresses = addresses
        elif parsed_addresses is not None:
            self.addresses = [_encode_address(a) for a in parsed_addresses]
        self.port = port
        self.weight = weight
        self.priority = priority
        self.server = server if server else None
        self.server_key = server.lower() if server else None
        self._properties: dict[bytes, bytes | None] | None = None
        self._decoded_properties: dict[str, str | None] | None = None
        if properties is None:
            self._txt_seen = False
        else:
            self._txt_seen = True
            if isinstance(properties, bytes):
                self._set_text(properties)
            else:
                self._set_properties(properties)
        self.host_ttl = host_ttl
        self.other_ttl = other_ttl
        self._new_records_futures: set[asyncio.Future] | None = None
        self._dns_address_cache: list[DNSAddress] | None = None
        self._dns_address_nsec_cache: DNSNsec | None = None
        self._dns_pointer_cache: DNSPointer | None = None
        self._dns_service_cache: DNSService | None = None
        self._dns_text_cache: DNSText | None = None
        self._get_address_and_nsec_records_cache: set[DNSRecord] | None = None
        self._query_record_types = {_TYPE_SRV, _TYPE_TXT, _TYPE_A, _TYPE_AAAA}

    def __repr__(self) -> str:
        return "{}({})".format(
            type(self).__name__,
            ", ".join(
                f"{name}={getattr(self, name)!r}"
                for name in (
                    "type",
                    "name",
                    "addresses",
                    "port",
                    "weight",
                    "priority",
                    "server",
                    "properties",
                    "interface_index",
                )
            ),
        )

    @property
    def addresses(self) -> list[bytes]:
        """IPv4 addresses of this service.

        Only IPv4 addresses are returned for backward compatibility.
        Use :meth:`addresses_by_version` or :meth:`parsed_addresses` to
        include IPv6 addresses as well.
        """
        return self.addresses_by_version(IPVersion.V4Only)

    @addresses.setter
    def addresses(self, value: Sequence[bytes | str]) -> None:
        """Replace the addresses list.

        This replaces all currently stored addresses, both IPv4 and IPv6.
        """
        self._ipv4_addresses.clear()
        self._ipv6_addresses.clear()
        self._dns_address_cache = None
        self._dns_address_nsec_cache = None
        self._get_address_and_nsec_records_cache = None

        for address in value:
            if len(address) == 16 and self.interface_index is not None:
                addr = ip_bytes_and_scope_to_address(address, self.interface_index)
            else:
                addr = cached_ip_addresses(address)
            if addr is None:
                raise TypeError(
                    "Addresses must either be IPv4 or IPv6 strings, bytes, or integers;"
                    f" got {address!r}. Hint: convert string addresses with socket.inet_pton"
                )
            if addr.version == 4:
                if TYPE_CHECKING:
                    assert isinstance(addr, ZeroconfIPv4Address)
                self._ipv4_addresses.append(addr)
            else:
                if TYPE_CHECKING:
                    assert isinstance(addr, ZeroconfIPv6Address)
                self._ipv6_addresses.append(addr)

    def addresses_by_version(self, version: IPVersion) -> list[bytes]:
        """List addresses matching IP version.

        Addresses are guaranteed to be returned in LIFO (last in, first out)
        order with IPv4 addresses first and IPv6 addresses second.

        This means the first address will always be the most recently added
        address of the given IP version.
        """
        version_value = version.value
        if version_value == _IPVersion_All_value:
            ip_v4_packed = [addr.packed for addr in self._ipv4_addresses]
            ip_v6_packed = [addr.packed for addr in self._ipv6_addresses]
            return [*ip_v4_packed, *ip_v6_packed]
        if version_value == _IPVersion_V4Only_value:
            return [addr.packed for addr in self._ipv4_addresses]
        return [addr.packed for addr in self._ipv6_addresses]

    def async_clear_cache(self) -> None:
        """Clear the cache for this service info."""
        self._dns_address_cache = None
        self._dns_address_nsec_cache = None
        self._dns_pointer_cache = None
        self._dns_service_cache = None
        self._dns_text_cache = None
        self._get_address_and_nsec_records_cache = None

    async def async_request(
        self,
        zc: Zeroconf,
        timeout: float,
        question_type: DNSQuestionType | None = None,
        addr: str | None = None,
        port: int = _MDNS_PORT,
    ) -> bool:
        """Populate this object from the network, returning True on success.

        Event loop flavor of request; waits up to timeout milliseconds
        for the answers to arrive, and addr and port direct the queries
        at a specific responder instead of the multicast group.
        """
        if not zc.started:
            await zc.async_wait_for_start()

        now = current_time_millis()

        if self._load_from_cache(zc, now):
            return True

        if TYPE_CHECKING:
            assert zc.loop is not None

        first_request = True
        delay = self._get_initial_delay()
        deadline = now + timeout
        send_at = now
        try:
            zc.async_add_listener(self, None)
            while not self._is_complete:
                now = current_time_millis()
                if self._is_denied or deadline <= now:
                    return False

                remaining = min(send_at, deadline) - now
                if remaining > 0:
                    await self.async_wait(remaining, zc.loop)
                    continue

                question_kind = question_type or (QU_QUESTION if first_request else QM_QUESTION)
                out = self._generate_request_query(zc, now, question_kind)
                first_request = False
                if out.questions:
                    # All questions may have been suppressed
                    # by the question history, so nothing to send,
                    # but keep waiting for answers in case another
                    # client on the network is asking the same
                    # question or they have not arrived yet.
                    zc.async_send(out, addr, port)
                send_at = now + delay + self._get_random_delay()
                if question_kind is QM_QUESTION and delay < _DUPLICATE_QUESTION_INTERVAL:
                    # If we just asked a QM question, we need to
                    # wait at least the duplicate question interval
                    # before asking another QM question otherwise
                    # its likely to be suppressed by the question
                    # history of the remote responder.
                    delay = _DUPLICATE_QUESTION_INTERVAL
        finally:
            zc.async_remove_listener(self)

        return True

    def async_update_records(self, zc: Zeroconf, now: float_, records: list[RecordUpdate_]) -> None:
        """Merge a batch of record updates into this object and wake any waiters."""
        new_records_futures = self._new_records_futures
        updated: bool = False
        nsec_records = None
        for record_update in records:
            record = record_update.new
            # NSEC records are processed last so a denial for an SRV target
            # learned later in the same batch is not discarded (wire order of
            # records in a response is not guaranteed).
            if type(record) is DNSNsec:
                if nsec_records is None:
                    nsec_records = []
                nsec_records.append(record)
                continue
            updated |= self._process_record_threadsafe(zc, record, now)
        if nsec_records is not None:
            for record in nsec_records:
                updated |= self._process_record_threadsafe(zc, record, now)
        if updated and new_records_futures:
            _resolve_all_futures_to_none(new_records_futures)

    async def async_wait(self, timeout: float, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Suspend the calling task for timeout milliseconds, or less when new records arrive."""
        if not self._new_records_futures:
            self._new_records_futures = set()
        await wait_for_future_set_or_timeout(
            loop or asyncio.get_running_loop(), self._new_records_futures, timeout
        )

    @property
    def decoded_properties(self) -> dict[str, str | None]:
        """Return properties as strings."""
        if self._decoded_properties is None:
            self._generate_decoded_properties()
        if TYPE_CHECKING:
            assert self._decoded_properties is not None
        return self._decoded_properties

    def dns_address_nsec(self, override_ttl: int_ | None = None) -> DNSNsec | None:
        """Return DNSNsec asserting which address types exist, or None if not applicable."""
        return self._dns_address_nsec(override_ttl)

    def dns_addresses(
        self,
        override_ttl: int_ | None = None,
        version: IPVersion = IPVersion.All,
    ) -> list[DNSAddress]:
        """Return matching DNSAddress from ServiceInfo."""
        return self._dns_addresses(override_ttl, version)

    def dns_nsec(self, missing_types: list[int], override_ttl: int_ | None = None) -> DNSNsec | None:
        """Deprecated: use dns_address_nsec instead; missing_types is ignored."""
        warnings.warn(
            "dns_nsec is deprecated, and will be removed in a future version. "
            "Use dns_address_nsec instead; missing_types is ignored.",
            DeprecationWarning,
            stacklevel=2,
        )
        return self._dns_address_nsec(override_ttl)

    def dns_pointer(self, override_ttl: int_ | None = None) -> DNSPointer:
        """Return DNSPointer from ServiceInfo."""
        return self._dns_pointer(override_ttl)

    def dns_service(self, override_ttl: int_ | None = None) -> DNSService:
        """Return DNSService from ServiceInfo."""
        return self._dns_service(override_ttl)

    def dns_text(self, override_ttl: int_ | None = None) -> DNSText:
        """Return DNSText from ServiceInfo."""
        return self._dns_text(override_ttl)

    def get_address_and_nsec_records(self, override_ttl: int_ | None = None) -> set[DNSRecord]:
        """Build a set of address records plus an NSEC asserting which address types exist."""
        return self._get_address_and_nsec_records(override_ttl)

    def get_name(self) -> str:
        """Instance name with the service type stripped."""
        return self._name[: len(self._name) - len(self.type) - 1]

    def ip_addresses_by_version(
        self, version: IPVersion
    ) -> list[ZeroconfIPv4Address] | list[ZeroconfIPv6Address]:
        """List ip_address objects matching IP version.

        Addresses are guaranteed to be returned in LIFO (last in, first out)
        order with IPv4 addresses first and IPv6 addresses second.

        This means the first address will always be the most recently added
        address of the given IP version.
        """
        return self._ip_addresses_by_version_value(version.value)

    def load_from_cache(self, zc: Zeroconf, now: float_ | None = None) -> bool:
        """Populate the service info from the cache.

        This method is designed to be threadsafe.
        """
        return self._load_from_cache(zc, now or current_time_millis())

    @property
    def name(self) -> str:
        """The complete instance name, including the type and domain."""
        return self._name

    @name.setter
    def name(self, name: str) -> None:
        """Replace the name and reset the key."""
        self._name = name
        self.key = name.lower()
        self._dns_service_cache = None
        self._dns_pointer_cache = None
        self._dns_text_cache = None

    def parsed_addresses(self, version: IPVersion = IPVersion.All) -> list[str]:
        """List addresses in their parsed string form.

        Addresses are guaranteed to be returned in LIFO (last in, first out)
        order with IPv4 addresses first and IPv6 addresses second.

        This means the first address will always be the most recently added
        address of the given IP version.
        """
        return [str_without_scope_id(addr) for addr in self._ip_addresses_by_version_value(version.value)]

    def parsed_scoped_addresses(self, version: IPVersion = IPVersion.All) -> list[str]:
        """Equivalent to parsed_addresses, with the exception that IPv6 Link-Local
        addresses are qualified with %<interface_index> when available

        Addresses are guaranteed to be returned in LIFO (last in, first out)
        order with IPv4 addresses first and IPv6 addresses second.

        This means the first address will always be the most recently added
        address of the given IP version.
        """
        return [str(addr) for addr in self._ip_addresses_by_version_value(version.value)]

    @property
    def properties(self) -> dict[bytes, bytes | None]:
        """Return properties as bytes."""
        if self._properties is None:
            self._unpack_text_into_properties()
        if TYPE_CHECKING:
            assert self._properties is not None
        return self._properties

    def request(
        self,
        zc: Zeroconf,
        timeout: float,
        question_type: DNSQuestionType | None = None,
        addr: str | None = None,
        port: int = _MDNS_PORT,
    ) -> bool:
        """Populate this object from the network, returning True on success.

        Waits up to timeout milliseconds for the answers to arrive; addr
        and port direct the queries at a specific responder instead of
        the multicast group.
        """
        assert zc.loop is not None, "Zeroconf instance must have a loop, was it not started?"
        assert zc.loop.is_running(), "Zeroconf instance loop must be running, was it already stopped?"
        if zc.loop == get_running_loop():
            raise RuntimeError("Use AsyncServiceInfo.async_request from the event loop")
        return bool(
            run_coro_with_timeout(
                self.async_request(zc, timeout, question_type, addr, port),
                zc.loop,
                timeout,
            )
        )

    def set_server_if_missing(self) -> None:
        """Set the server if it is missing.

        This function is for backwards compatibility.
        """
        if self.server is None:
            self.server = self._name
            self.server_key = self.key

    def _add_question_with_known_answers(
        self,
        out: DNSOutgoing,
        qu_question: bool,
        question_history: QuestionHistory,
        cache: DNSCache,
        now: float_,
        name: str_,
        type_: int_,
        class_: int_,
        skip_if_known_answers: bool,
    ) -> None:
        """Add a question with known answers if its not suppressed."""
        known_answers = {
            answer for answer in cache.get_all_by_details(name, type_, class_) if not answer.is_stale(now)
        }
        if skip_if_known_answers and known_answers:
            return
        question = DNSQuestion(name, type_, class_)
        if qu_question:
            question.unicast = True
        elif question_history.suppresses(question, now, known_answers):
            return
        else:
            question_history.add_question_at_time(question, now, known_answers)
        out.add_question(question)
        for answer in known_answers:
            out.add_answer_at_time(answer, now)

    def _dns_address_nsec(self, override_ttl: int_ | None) -> DNSNsec | None:
        cacheable = override_ttl is None
        if self._dns_address_nsec_cache is not None and cacheable:
            return self._dns_address_nsec_cache
        # RFC 6762 §6.1: the type bitmap lists the rrtypes that exist at the
        # name. Both families present leaves nothing to deny; neither leaves
        # nothing to assert (an empty bitmap is unencodable).
        has_v4 = bool(self._ipv4_addresses)
        has_v6 = bool(self._ipv6_addresses)
        if has_v4 == has_v6:
            return None
        assert self.server is not None, "Service server must be set for NSEC record."
        record = DNSNsec(
            self.server,
            _TYPE_NSEC,
            _CLASS_IN_UNIQUE,
            override_ttl if override_ttl is not None else self.host_ttl,
            self.server,
            [_TYPE_A] if has_v4 else [_TYPE_AAAA],
            0.0,
        )
        if cacheable:
            self._dns_address_nsec_cache = record
        return record

    def _dns_addresses(
        self,
        override_ttl: int_ | None,
        version: IPVersion,
    ) -> list[DNSAddress]:
        """Return matching DNSAddress from ServiceInfo."""
        cacheable = version is IPVersion.All and override_ttl is None
        if self._dns_address_cache is not None and cacheable:
            return self._dns_address_cache
        name = self.server or self._name
        ttl = override_ttl if override_ttl is not None else self.host_ttl
        class_ = _CLASS_IN_UNIQUE
        version_value = version.value
        records = [
            DNSAddress(
                name,
                _TYPE_AAAA if ip_addr.version == 6 else _TYPE_A,
                class_,
                ttl,
                ip_addr.packed,
                created=0.0,
            )
            for ip_addr in self._ip_addresses_by_version_value(version_value)
        ]
        if cacheable:
            self._dns_address_cache = records
        return records

    def _dns_pointer(self, override_ttl: int_ | None) -> DNSPointer:
        """Return DNSPointer from ServiceInfo."""
        cacheable = override_ttl is None
        if self._dns_pointer_cache is not None and cacheable:
            return self._dns_pointer_cache
        record = DNSPointer(
            self.type,
            _TYPE_PTR,
            _CLASS_IN,
            override_ttl if override_ttl is not None else self.other_ttl,
            self._name,
            0.0,
        )
        if cacheable:
            self._dns_pointer_cache = record
        return record

    def _dns_service(self, override_ttl: int_ | None) -> DNSService:
        """Return DNSService from ServiceInfo."""
        cacheable = override_ttl is None
        if self._dns_service_cache is not None and cacheable:
            return self._dns_service_cache
        port = self.port
        if TYPE_CHECKING:
            assert isinstance(port, int)
        record = DNSService(
            self._name,
            _TYPE_SRV,
            _CLASS_IN_UNIQUE,
            override_ttl if override_ttl is not None else self.host_ttl,
            self.priority,
            self.weight,
            port,
            self.server or self._name,
            0.0,
        )
        if cacheable:
            self._dns_service_cache = record
        return record

    def _dns_text(self, override_ttl: int_ | None) -> DNSText:
        """Return DNSText from ServiceInfo."""
        cacheable = override_ttl is None
        if self._dns_text_cache is not None and cacheable:
            return self._dns_text_cache
        record = DNSText(
            self._name,
            _TYPE_TXT,
            _CLASS_IN_UNIQUE,
            override_ttl if override_ttl is not None else self.other_ttl,
            self.text,
            0.0,
        )
        if cacheable:
            self._dns_text_cache = record
        return record

    def _generate_decoded_properties(self) -> None:
        """Generates decoded properties from the properties"""
        self._decoded_properties = {
            k.decode("ascii", "replace"): None if v is None else v.decode("utf-8", "replace")
            for k, v in self.properties.items()
        }

    def _generate_request_query(
        self, zc: Zeroconf, now: float_, question_type: DNSQuestionType
    ) -> DNSOutgoing:
        """Generate the request query."""
        out = DNSOutgoing(_FLAGS_QR_QUERY)
        name = self._name
        server = self.server or name
        cache = zc.cache
        history = zc.question_history
        qu_question = question_type is QU_QUESTION
        if _TYPE_SRV in self._query_record_types:
            self._add_question_with_known_answers(
                out, qu_question, history, cache, now, name, _TYPE_SRV, _CLASS_IN, True
            )
        if _TYPE_TXT in self._query_record_types:
            self._add_question_with_known_answers(
                out, qu_question, history, cache, now, name, _TYPE_TXT, _CLASS_IN, True
            )
        if _TYPE_A in self._query_record_types:
            self._add_question_with_known_answers(
                out, qu_question, history, cache, now, server, _TYPE_A, _CLASS_IN, False
            )
        if _TYPE_AAAA in self._query_record_types:
            self._add_question_with_known_answers(
                out, qu_question, history, cache, now, server, _TYPE_AAAA, _CLASS_IN, False
            )
        return out

    def _get_address_and_nsec_records(self, override_ttl: int_ | None) -> set[DNSRecord]:
        """Build a set of address records plus an NSEC asserting which address types exist."""
        cacheable = override_ttl is None
        if self._get_address_and_nsec_records_cache is not None and cacheable:
            return self._get_address_and_nsec_records_cache
        records: set[DNSRecord] = set(self._dns_addresses(override_ttl, IPVersion.All))
        nsec = self._dns_address_nsec(override_ttl)
        if nsec is not None:
            records.add(nsec)
        if cacheable:
            self._get_address_and_nsec_records_cache = records
        return records

    def _get_address_records_from_cache_by_type(self, zc: Zeroconf, _type: int_) -> list[DNSAddress]:
        """Get the addresses from the cache."""
        if self.server_key is None:
            return []
        cache = zc.cache
        if TYPE_CHECKING:
            records = cast(
                list[DNSAddress],
                cache.get_all_by_details(self.server_key, _type, _CLASS_IN),
            )
        else:
            records = cache.get_all_by_details(self.server_key, _type, _CLASS_IN)
        return records

    def _get_initial_delay(self) -> float_:
        return _LISTENER_TIME

    def _get_ip_addresses_from_cache_lifo(
        self, zc: Zeroconf, now: float_, type: int_
    ) -> list[ZeroconfIPv4Address | ZeroconfIPv6Address]:
        """Set IPv6 addresses from the cache."""
        address_list: list[ZeroconfIPv4Address | ZeroconfIPv6Address] = []
        for record in self._get_address_records_from_cache_by_type(zc, type):
            if record.is_expired(now):
                continue
            ip_addr = get_ip_address_object_from_record(record)
            if ip_addr is None:
                continue
            # The cache keeps scoped and unscoped link-local AAAA
            # records as separate entries because DNSAddress equality
            # includes scope_id. Collapse them here so each address
            # appears once; the scoped variant wins so callers of
            # parsed_scoped_addresses() get a %<interface_index>-
            # qualified link-local address when one was observed.
            existing_idx = _index_of_same_address(address_list, ip_addr)
            if existing_idx == -1:
                address_list.append(ip_addr)
                continue
            # Move the re-seen address to the end so the later observation
            # wins both in value (scope) and in LIFO position after reverse.
            existing = address_list.pop(existing_idx)
            address_list.append(ip_addr if _has_more_scope_info(ip_addr, existing) else existing)
        address_list.reverse()  # Reverse to get LIFO order
        return address_list

    def _get_random_delay(self) -> int_:
        return randint(*_AVOID_SYNC_DELAY_RANDOM_INTERVAL)

    def _ip_addresses_by_version_value(
        self, version_value: int_
    ) -> list[ZeroconfIPv4Address] | list[ZeroconfIPv6Address]:
        """Backend for addresses_by_version that uses the raw value."""
        if version_value == _IPVersion_All_value:
            return [*self._ipv4_addresses, *self._ipv6_addresses]  # type: ignore[return-value]
        if version_value == _IPVersion_V4Only_value:
            return self._ipv4_addresses
        return self._ipv6_addresses

    @property
    def _is_complete(self) -> bool:
        """The ServiceInfo has all expected properties.

        RFC 6763 section 6 requires every DNS-SD service to have a TXT record,
        so a service is not complete until one has been seen. An empty TXT
        record counts as seen, as does an NSEC record denying its existence
        (RFC 6762 section 6.1); a missing one does not.
        """
        return bool(self._txt_seen and (self._ipv4_addresses or self._ipv6_addresses))

    @property
    def _is_denied(self) -> bool:
        """Every address type this request needs was denied via NSEC (RFC 6762 section 6.1)."""
        query_types = self._query_record_types
        return (_TYPE_A not in query_types or (self._ipv4_denied and not self._ipv4_addresses)) and (
            _TYPE_AAAA not in query_types or (self._ipv6_denied and not self._ipv6_addresses)
        )

    def _load_from_cache(self, zc: Zeroconf, now: float_) -> bool:
        """Populate the service info from the cache.

        This method is designed to be threadsafe.
        """
        cache = zc.cache
        original_server_key = self.server_key
        # Denials are only trusted until the next cache load re-derives them.
        self._ipv4_denied = False
        self._ipv6_denied = False
        cached_srv_record = cache.get_by_details(self._name, _TYPE_SRV, _CLASS_IN)
        if cached_srv_record:
            self._process_record_threadsafe(zc, cached_srv_record, now)
        cached_txt_record = cache.get_by_details(self._name, _TYPE_TXT, _CLASS_IN)
        if cached_txt_record:
            self._process_record_threadsafe(zc, cached_txt_record, now)
        if not self._txt_seen:
            cached_nsec_record = cache.get_by_details(self._name, _TYPE_NSEC, _CLASS_IN)
            if cached_nsec_record:
                self._process_record_threadsafe(zc, cached_nsec_record, now)
        if original_server_key == self.server_key:
            # If there is a srv which changes the server_key,
            # A, AAAA, and the server NSEC will already be loaded
            # from the cache and we do not want to do it twice
            for record in self._get_address_records_from_cache_by_type(zc, _TYPE_A):
                self._process_record_threadsafe(zc, record, now)
            for record in self._get_address_records_from_cache_by_type(zc, _TYPE_AAAA):
                self._process_record_threadsafe(zc, record, now)
            if self.server_key and not self._is_complete:
                cached_server_nsec_record = cache.get_by_details(self.server_key, _TYPE_NSEC, _CLASS_IN)
                if cached_server_nsec_record:
                    self._process_record_threadsafe(zc, cached_server_nsec_record, now)
        return self._is_complete

    def _load_records_for_new_server_from_cache(self, zc: Zeroconf, now: float_) -> None:
        """Re-derive per-host state, denials included, after the SRV target changed."""
        self._ipv4_denied = False
        self._ipv6_denied = False
        self._set_ipv4_addresses_from_cache(zc, now)
        self._set_ipv6_addresses_from_cache(zc, now)
        if TYPE_CHECKING:
            assert self.server_key is not None
        cache = zc.cache
        cached_server_nsec_record = cache.get_by_details(self.server_key, _TYPE_NSEC, _CLASS_IN)
        if cached_server_nsec_record:
            self._process_record_threadsafe(zc, cached_server_nsec_record, now)

    def _process_nsec_record(self, record: DNSNsec, record_key: str_) -> bool:
        """Record the denials asserted by an NSEC record (RFC 6762 §6.1)."""
        rdtypes = record.rdtypes
        updated = False
        if record_key == self.server_key:
            # Each NSEC is an authoritative snapshot of what exists at the
            # host, so recompute both flags instead of accumulating denials.
            ipv4_denied = _TYPE_A not in rdtypes
            ipv6_denied = _TYPE_AAAA not in rdtypes
            if ipv4_denied != self._ipv4_denied or ipv6_denied != self._ipv6_denied:
                self._ipv4_denied = ipv4_denied
                self._ipv6_denied = ipv6_denied
                updated = True
        if (
            record_key == self.key
            and not self._txt_seen
            and _TYPE_SRV in rdtypes
            and _TYPE_TXT not in rdtypes
        ):
            # Requiring the SRV bit keeps older python-zeroconf NSECs, which listed the
            # missing address types, from being misread as a TXT denial.
            self._txt_seen = True
            updated = True
        return updated

    def _process_record_threadsafe(self, zc: Zeroconf, record: DNSRecord, now: float_) -> bool:
        """Thread safe record updating.

        Returns True if a new record was added.
        """
        if record.is_expired(now):
            return False

        record_key = record.key
        record_type = type(record)
        if record_type is DNSAddress and record_key == self.server_key:
            dns_address_record = record
            if TYPE_CHECKING:
                assert isinstance(dns_address_record, DNSAddress)
            ip_addr = get_ip_address_object_from_record(dns_address_record)
            if ip_addr is None:
                log.warning(
                    "Encountered invalid address while processing %s: %s",
                    dns_address_record,
                    dns_address_record.address,
                )
                return False

            if ip_addr.version == 4:
                if TYPE_CHECKING:
                    assert isinstance(ip_addr, ZeroconfIPv4Address)
                ipv4_addresses = self._ipv4_addresses
                if ip_addr not in ipv4_addresses:
                    ipv4_addresses.insert(0, ip_addr)
                    return True
                # Use int() to compare the addresses as integers
                # since by default IPv4Address.__eq__ compares the
                # the addresses on version and int which more than
                # we need here since we know the version is 4.
                if ip_addr.zc_integer != ipv4_addresses[0].zc_integer:
                    ipv4_addresses.remove(ip_addr)
                    ipv4_addresses.insert(0, ip_addr)

                return False

            if TYPE_CHECKING:
                assert isinstance(ip_addr, ZeroconfIPv6Address)
            return self._upsert_ipv6_address(ip_addr)

        if record_type is DNSNsec:
            if record_key not in (self.server_key, self.key):
                return False
            dns_nsec_record = record
            if TYPE_CHECKING:
                assert isinstance(dns_nsec_record, DNSNsec)
            return self._process_nsec_record(dns_nsec_record, record_key)

        if record_key != self.key:
            return False

        if record_type is DNSText:
            dns_text_record = record
            if TYPE_CHECKING:
                assert isinstance(dns_text_record, DNSText)
            self._set_text(dns_text_record.text)
            self._txt_seen = True
            return True

        if record_type is DNSService:
            dns_service_record = record
            if TYPE_CHECKING:
                assert isinstance(dns_service_record, DNSService)
            old_server_key = self.server_key
            self._name = dns_service_record.name
            self.key = dns_service_record.key
            self.server = dns_service_record.server
            self.server_key = dns_service_record.server_key
            self.port = dns_service_record.port
            self.weight = dns_service_record.weight
            self.priority = dns_service_record.priority
            if old_server_key != self.server_key:
                self._load_records_for_new_server_from_cache(zc, now)
            return True

        return False

    def _set_ipv4_addresses_from_cache(self, zc: Zeroconf, now: float_) -> None:
        """Set IPv4 addresses from the cache."""
        if TYPE_CHECKING:
            self._ipv4_addresses = cast(
                list[ZeroconfIPv4Address],
                self._get_ip_addresses_from_cache_lifo(zc, now, _TYPE_A),
            )
        else:
            self._ipv4_addresses = self._get_ip_addresses_from_cache_lifo(zc, now, _TYPE_A)

    def _set_ipv6_addresses_from_cache(self, zc: Zeroconf, now: float_) -> None:
        """Set IPv6 addresses from the cache."""
        if TYPE_CHECKING:
            self._ipv6_addresses = cast(
                list[ZeroconfIPv6Address],
                self._get_ip_addresses_from_cache_lifo(zc, now, _TYPE_AAAA),
            )
        else:
            self._ipv6_addresses = self._get_ip_addresses_from_cache_lifo(zc, now, _TYPE_AAAA)

    def _set_properties(self, properties: dict[str | bytes, str | bytes | None]) -> None:
        list_: list[bytes] = []
        properties_contain_str = False
        result = b""
        for key, value in properties.items():
            if isinstance(key, str):
                key = key.encode("utf-8")  # noqa: PLW2901
                properties_contain_str = True

            record = key
            if value is not None:
                if not isinstance(value, bytes):
                    value = str(value).encode("utf-8")  # noqa: PLW2901
                    properties_contain_str = True
                record += b"=" + value
            list_.append(record)
        for item in list_:
            result = b"".join((result, bytes((len(item),)), item))
        if not properties_contain_str:
            # If there are no str keys or values, we can use the properties
            # as-is, without decoding them, otherwise calling
            # self.properties will lazy decode them, which is expensive.
            if TYPE_CHECKING:
                self._properties = cast(dict[bytes, bytes | None], properties)
            else:
                self._properties = properties
        self.text = result

    def _set_text(self, text: bytes) -> None:
        if text == self.text:
            return
        self.text = text
        # Clear the properties cache
        self._properties = None
        self._decoded_properties = None

    def _unpack_text_into_properties(self) -> None:
        """Unpacks the text field into properties"""
        text = self.text
        end = len(text)
        if end == 0:
            # Properties should be set atomically
            # in case another thread is reading them
            self._properties = {}
            return

        index = 0
        properties: dict[bytes, bytes | None] = {}
        while index < end:
            length = text[index]
            index += 1
            key_value = text[index : index + length]
            key, sep, value = key_value.partition(b"=")
            if key not in properties:
                # RFC 6763 section 6.4 distinguishes a key with no '=' (a
                # boolean attribute: present, no value) from `key=` (present
                # with an empty value), so test the separator, not the value.
                properties[key] = value if sep else None
            index += length

        self._properties = properties

    def _upsert_ipv6_address(self, ip_addr: ZeroconfIPv6Address) -> bool:
        """Insert or update an IPv6 address in LIFO order.

        Compares by integer (not IPv6Address equality, which respects
        scope_id) so the same link-local address received first without
        scope (IPv4 socket) and then with scope (IPv6 socket) collapses
        to one entry. The scoped variant wins so parsed_scoped_addresses()
        can return a qualified address.
        """
        ipv6_addresses = self._ipv6_addresses
        existing_idx = _index_of_same_address(ipv6_addresses, ip_addr)
        if existing_idx == -1:
            ipv6_addresses.insert(0, ip_addr)
            return True
        existing = ipv6_addresses[existing_idx]
        if _has_more_scope_info(ip_addr, existing):
            ipv6_addresses.pop(existing_idx)
            ipv6_addresses.insert(0, ip_addr)
            return True
        if existing_idx != 0:
            ipv6_addresses.pop(existing_idx)
            ipv6_addresses.insert(0, existing)
        return False


class AddressResolver(ServiceInfo):
    """Resolve a host name to an IP address."""

    def __init__(self, server: str) -> None:
        """Initialize the AddressResolver."""
        super().__init__(server, server, server=server)
        self._query_record_types = _TYPE_A_AAAA_RECORDS

    @property
    def _is_complete(self) -> bool:
        """The ServiceInfo has all expected properties."""
        return bool(self._ipv4_addresses) or bool(self._ipv6_addresses)


class AddressResolverIPv4(ServiceInfo):
    """Resolve a host name to an IPv4 address."""

    def __init__(self, server: str) -> None:
        """Initialize the AddressResolver."""
        super().__init__(server, server, server=server)
        self._query_record_types = _TYPE_A_RECORDS

    @property
    def _is_complete(self) -> bool:
        """The ServiceInfo has all expected properties."""
        return bool(self._ipv4_addresses)


class AddressResolverIPv6(ServiceInfo):
    """Resolve a host name to an IPv6 address."""

    def __init__(self, server: str) -> None:
        """Initialize the AddressResolver."""
        super().__init__(server, server, server=server)
        self._query_record_types = _TYPE_AAAA_RECORDS

    @property
    def _is_complete(self) -> bool:
        """The ServiceInfo has all expected properties."""
        return bool(self._ipv6_addresses)


class AsyncServiceInfo(ServiceInfo):
    """An async version of ServiceInfo."""
