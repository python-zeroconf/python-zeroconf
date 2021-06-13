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

import errno
import itertools
import platform
import select
import socket
import threading
from types import TracebackType  # noqa # used in type hints
from typing import Dict, List, Optional, Type, Union, cast

from .const import (
    _CACHE_CLEANUP_INTERVAL,
    _CHECK_TIME,
    _CLASS_IN,
    _DNS_OTHER_TTL,
    _DNS_PORT,
    _FLAGS_AA,
    _FLAGS_QR_QUERY,
    _FLAGS_QR_RESPONSE,
    _MAX_MSG_ABSOLUTE,
    _MDNS_ADDR,
    _MDNS_ADDR6,
    _MDNS_PORT,
    _REGISTER_TIME,
    _SERVICE_TYPE_ENUMERATION_NAME,
    _TYPE_A,
    _TYPE_ANY,
    _TYPE_PTR,
    _TYPE_SRV,
    _TYPE_TXT,
    _UNREGISTER_TIME,
)
from .dns import DNSAddress, DNSCache, DNSIncoming, DNSOutgoing, DNSPointer, DNSQuestion, DNSRecord
from .exceptions import NonUniqueNameException
from .logger import QuietLogger, log
from .services import (
    RecordUpdateListener,
    ServiceBrowser,
    ServiceInfo,
    ServiceListener,
    instance_name_from_service_info,
)
from .services.registry import ServiceRegistry
from .utils.name import service_type_name
from .utils.net import (
    IPVersion,
    InterfaceChoice,
    InterfacesType,
    autodetect_ip_version,
    can_send_to,
    create_sockets,
)
from .utils.time import current_time_millis, millis_to_seconds


class NotifyListener:
    """Receive notifications Zeroconf.notify_all is called."""

    def notify_all(self) -> None:
        """Called when Zeroconf.notify_all is called."""
        raise NotImplementedError()


class Engine(threading.Thread):

    """An engine wraps read access to sockets, allowing objects that
    need to receive data from sockets to be called back when the
    sockets are ready.

    A reader needs a handle_read() method, which is called when the socket
    it is interested in is ready for reading.

    Writers are not implemented here, because we only send short
    packets.
    """

    def __init__(self, zc: 'Zeroconf') -> None:
        threading.Thread.__init__(self)
        self.daemon = True
        self.zc = zc
        self.readers = {}  # type: Dict[socket.socket, Listener]
        self.timeout = 5
        self.condition = threading.Condition()
        self.socketpair = socket.socketpair()
        self._last_cache_cleanup = 0.0
        self.name = "zeroconf-Engine-%s" % (getattr(self, 'native_id', self.ident),)

    def run(self) -> None:
        while not self.zc.done:
            try:
                rr, _wr, _er = select.select([*self.readers.keys(), self.socketpair[0]], [], [], self.timeout)

                if self.zc.done:
                    return

                for socket_ in rr:
                    reader = self.readers.get(socket_)
                    if reader:
                        reader.handle_read(socket_)

                if self.socketpair[0] in rr:
                    # Clear the socket's buffer
                    self.socketpair[0].recv(128)

            except (select.error, socket.error) as e:
                # If the socket was closed by another thread, during
                # shutdown, ignore it and exit
                if e.args[0] not in (errno.EBADF, errno.ENOTCONN) or not self.zc.done:
                    raise

            now = current_time_millis()
            if now - self._last_cache_cleanup >= _CACHE_CLEANUP_INTERVAL:
                self._last_cache_cleanup = now
                self.zc.record_manager.updates(now, list(self.zc.cache.expire(now)))
                self.zc.record_manager.updates_complete()

        self.socketpair[0].close()
        self.socketpair[1].close()

    def _notify(self) -> None:
        self.condition.notify()
        try:
            self.socketpair[1].send(b'x')
        except socket.error:
            # The socketpair may already be closed during shutdown, ignore it
            if not self.zc.done:
                raise

    def add_reader(self, reader: 'Listener', socket_: socket.socket) -> None:
        with self.condition:
            self.readers[socket_] = reader
            self._notify()

    def del_reader(self, socket_: socket.socket) -> None:
        with self.condition:
            del self.readers[socket_]
            self._notify()


class Listener(QuietLogger):

    """A Listener is used by this module to listen on the multicast
    group to which DNS messages are sent, allowing the implementation
    to cache information as it arrives.

    It requires registration with an Engine object in order to have
    the read() method called when a socket is available for reading."""

    def __init__(self, zc: 'Zeroconf') -> None:
        self.zc = zc
        self.data = None  # type: Optional[bytes]

    def handle_read(self, socket_: socket.socket) -> None:
        try:
            data, (addr, port, *_v6) = socket_.recvfrom(_MAX_MSG_ABSOLUTE)
        except Exception:  # pylint: disable=broad-except
            self.log_exception_warning('Error reading from socket %d', socket_.fileno())
            return

        if self.data == data:
            log.debug(
                'Ignoring duplicate message received from %r:%r (socket %d) (%d bytes) as [%r]',
                addr,
                port,
                socket_.fileno(),
                len(data),
                data,
            )
            return

        self.data = data
        msg = DNSIncoming(data)
        if msg.valid:
            log.debug(
                'Received from %r:%r (socket %d): %r (%d bytes) as [%r]',
                addr,
                port,
                socket_.fileno(),
                msg,
                len(data),
                data,
            )
        else:
            log.debug(
                'Received from %r:%r (socket %d): (%d bytes) [%r]',
                addr,
                port,
                socket_.fileno(),
                len(data),
                data,
            )

        if not msg.valid:
            pass

        elif msg.is_query():
            # Always multicast responses
            if port == _MDNS_PORT:
                self.zc.handle_query(msg, None, _MDNS_PORT)

            # If it's not a multicast query, reply via unicast
            # and multicast
            elif port == _DNS_PORT:
                self.zc.handle_query(msg, addr, port)
                self.zc.handle_query(msg, None, _MDNS_PORT)

        else:
            self.zc.handle_response(msg)


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


class Zeroconf(QuietLogger):

    """Implementation of Zeroconf Multicast DNS Service Discovery

    Supports registration, unregistration, queries and browsing.
    """

    def __init__(
        self,
        interfaces: InterfacesType = InterfaceChoice.All,
        unicast: bool = False,
        ip_version: Optional[IPVersion] = None,
        apple_p2p: bool = False,
    ) -> None:
        """Creates an instance of the Zeroconf class, establishing
        multicast communications, listening and reaping threads.

        :param interfaces: :class:`InterfaceChoice` or a list of IP addresses
            (IPv4 and IPv6) and interface indexes (IPv6 only).

            IPv6 notes for non-POSIX systems:
            * `InterfaceChoice.All` is an alias for `InterfaceChoice.Default`
              on Python versions before 3.8.

            Also listening on loopback (``::1``) doesn't work, use a real address.
        :param ip_version: IP versions to support. If `choice` is a list, the default is detected
            from it. Otherwise defaults to V4 only for backward compatibility.
        :param apple_p2p: use AWDL interface (only macOS)
        """
        if ip_version is None:
            ip_version = autodetect_ip_version(interfaces)

        # hook for threads
        self._GLOBAL_DONE = False
        self.unicast = unicast

        if apple_p2p and not platform.system() == 'Darwin':
            raise RuntimeError('Option `apple_p2p` is not supported on non-Apple platforms.')

        self._listen_socket, self._respond_sockets = create_sockets(
            interfaces, unicast, ip_version, apple_p2p=apple_p2p
        )
        log.debug('Listen socket %s, respond sockets %s', self._listen_socket, self._respond_sockets)
        self.multi_socket = unicast or interfaces is not InterfaceChoice.Default

        self._notify_listeners: List[NotifyListener] = []
        self.browsers: Dict[ServiceListener, ServiceBrowser] = {}
        self.registry = ServiceRegistry()
        self.query_handler = QueryHandler(self.registry)
        self.cache = DNSCache()
        self.record_manager = RecordManager(self)

        self.condition = threading.Condition()

        self.engine = Engine(self)
        self.listener = Listener(self)
        if not unicast:
            self.engine.add_reader(self.listener, cast(socket.socket, self._listen_socket))
        if self.multi_socket:
            for s in self._respond_sockets:
                self.engine.add_reader(self.listener, s)
        # Start the engine only after all
        # the readers have been added to avoid
        # missing any packets that are on the wire
        self.engine.start()

    @property
    def done(self) -> bool:
        return self._GLOBAL_DONE

    @property
    def listeners(self) -> List[RecordUpdateListener]:
        return self.record_manager.listeners

    def wait(self, timeout: float) -> None:
        """Calling thread waits for a given number of milliseconds or
        until notified."""
        with self.condition:
            self.condition.wait(millis_to_seconds(timeout))

    def notify_all(self) -> None:
        """Notifies all waiting threads"""
        with self.condition:
            self.condition.notify_all()
            for listener in self._notify_listeners:
                listener.notify_all()

    def get_service_info(self, type_: str, name: str, timeout: int = 3000) -> Optional[ServiceInfo]:
        """Returns network's service information for a particular
        name and type, or None if no service matches by the timeout,
        which defaults to 3 seconds."""
        info = ServiceInfo(type_, name)
        if info.request(self, timeout):
            return info
        return None

    def add_notify_listener(self, listener: NotifyListener) -> None:
        """Adds a listener to receive notify_all events."""
        self._notify_listeners.append(listener)

    def remove_notify_listener(self, listener: NotifyListener) -> None:
        """Removes a listener from the set that is currently listening."""
        self._notify_listeners.remove(listener)

    def add_service_listener(self, type_: str, listener: ServiceListener) -> None:
        """Adds a listener for a particular service type.  This object
        will then have its add_service and remove_service methods called when
        services of that type become available and unavailable."""
        self.remove_service_listener(listener)
        self.browsers[listener] = ServiceBrowser(self, type_, listener)

    def remove_service_listener(self, listener: ServiceListener) -> None:
        """Removes a listener from the set that is currently listening."""
        if listener in self.browsers:
            self.browsers[listener].cancel()
            del self.browsers[listener]

    def remove_all_service_listeners(self) -> None:
        """Removes a listener from the set that is currently listening."""
        for listener in list(self.browsers):
            self.remove_service_listener(listener)

    def register_service(
        self,
        info: ServiceInfo,
        ttl: Optional[int] = None,
        allow_name_change: bool = False,
        cooperating_responders: bool = False,
    ) -> None:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service.  The name of the service may be changed if needed to make
        it unique on the network. Additionally multiple cooperating responders
        can register the same service on the network for resilience
        (if you want this behavior set `cooperating_responders` to `True`)."""
        if ttl is not None:
            # ttl argument is used to maintain backward compatibility
            # Setting TTLs via ServiceInfo is preferred
            info.host_ttl = ttl
            info.other_ttl = ttl
        self.check_service(info, allow_name_change, cooperating_responders)
        self.registry.add(info)
        self._broadcast_service(info, _REGISTER_TIME, None)

    def update_service(self, info: ServiceInfo) -> None:
        """Registers service information to the network with a default TTL.
        Zeroconf will then respond to requests for information for that
        service."""

        self.registry.update(info)
        self._broadcast_service(info, _REGISTER_TIME, None)

    def _broadcast_service(self, info: ServiceInfo, interval: int, ttl: Optional[int]) -> None:
        """Send a broadcasts to announce a service at intervals."""
        now = current_time_millis()
        next_time = now
        i = 0
        while i < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue

            self.send_service_broadcast(info, ttl)
            i += 1
            next_time += interval

    def send_service_broadcast(self, info: ServiceInfo, ttl: Optional[int]) -> None:
        """Send a broadcast to announce a service."""
        self.send(self.generate_service_broadcast(info, ttl))

    def generate_service_broadcast(self, info: ServiceInfo, ttl: Optional[int]) -> DNSOutgoing:
        """Generate a broadcast to announce a service."""
        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
        self._add_broadcast_answer(out, info, ttl)
        return out

    def send_service_query(self, info: ServiceInfo) -> None:
        """Send a query to lookup a service."""
        self.send(self.generate_service_query(info))

    def generate_service_query(self, info: ServiceInfo) -> DNSOutgoing:  # pylint: disable=no-self-use
        """Generate a query to lookup a service."""
        out = DNSOutgoing(_FLAGS_QR_QUERY | _FLAGS_AA)
        out.add_question(DNSQuestion(info.type, _TYPE_PTR, _CLASS_IN))
        out.add_authorative_answer(info.dns_pointer())
        return out

    def _add_broadcast_answer(  # pylint: disable=no-self-use
        self, out: DNSOutgoing, info: ServiceInfo, override_ttl: Optional[int]
    ) -> None:
        """Add answers to broadcast a service."""
        other_ttl = info.other_ttl if override_ttl is None else override_ttl
        host_ttl = info.host_ttl if override_ttl is None else override_ttl
        out.add_answer_at_time(info.dns_pointer(override_ttl=other_ttl), 0)
        out.add_answer_at_time(info.dns_service(override_ttl=host_ttl), 0)
        out.add_answer_at_time(info.dns_text(override_ttl=other_ttl), 0)
        for dns_address in info.dns_addresses(override_ttl=host_ttl):
            out.add_answer_at_time(dns_address, 0)

    def unregister_service(self, info: ServiceInfo) -> None:
        """Unregister a service."""
        self.registry.remove(info)
        self._broadcast_service(info, _UNREGISTER_TIME, 0)

    def unregister_all_services(self) -> None:
        """Unregister all registered services."""
        service_infos = self.registry.get_service_infos()
        if not service_infos:
            return
        now = current_time_millis()
        next_time = now
        i = 0
        while i < 3:
            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue
            out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
            for info in service_infos:
                self._add_broadcast_answer(out, info, 0)
            self.send(out)
            i += 1
            next_time += _UNREGISTER_TIME

    def check_service(
        self, info: ServiceInfo, allow_name_change: bool, cooperating_responders: bool = False
    ) -> None:
        """Checks the network for a unique service name, modifying the
        ServiceInfo passed in if it is not unique."""
        instance_name = instance_name_from_service_info(info)
        if cooperating_responders:
            return
        next_instance_number = 2
        next_time = now = current_time_millis()
        i = 0
        while i < 3:
            # check for a name conflict
            while self.cache.current_entry_with_name_and_alias(info.type, info.name):
                if not allow_name_change:
                    raise NonUniqueNameException

                # change the name and look for a conflict
                info.name = '%s-%s.%s' % (instance_name, next_instance_number, info.type)
                next_instance_number += 1
                service_type_name(info.name)
                next_time = now
                i = 0

            if now < next_time:
                self.wait(next_time - now)
                now = current_time_millis()
                continue

            self.send_service_query(info)
            i += 1
            next_time += _CHECK_TIME

    def add_listener(
        self, listener: RecordUpdateListener, question: Optional[Union[DNSQuestion, List[DNSQuestion]]]
    ) -> None:
        """Adds a listener for a given question.  The listener will have
        its update_record method called when information is available to
        answer the question(s)."""
        self.record_manager.add_listener(listener, question)

    def remove_listener(self, listener: RecordUpdateListener) -> None:
        """Removes a listener."""
        self.record_manager.remove_listener(listener)

    def handle_response(self, msg: DNSIncoming) -> None:
        """Deal with incoming response packets.  All answers
        are held in the cache, and listeners are notified."""
        self.record_manager.updates_from_response(msg)

    def handle_query(self, msg: DNSIncoming, addr: Optional[str], port: int) -> None:
        """Deal with incoming query packets.  Provides a response if
        possible."""
        out = self.query_handler.response(msg, port != _MDNS_PORT)
        if out:
            self.send(out, addr, port)

    def send(self, out: DNSOutgoing, addr: Optional[str] = None, port: int = _MDNS_PORT) -> None:
        """Sends an outgoing packet."""
        packets = out.packets()
        packet_num = 0
        for packet in packets:
            packet_num += 1
            if len(packet) > _MAX_MSG_ABSOLUTE:
                self.log_warning_once("Dropping %r over-sized packet (%d bytes) %r", out, len(packet), packet)
                return
            log.debug('Sending (%d bytes #%d) %r as %r...', len(packet), packet_num, out, packet)
            for s in self._respond_sockets:
                if self._GLOBAL_DONE:
                    return
                try:
                    if addr is None:
                        real_addr = _MDNS_ADDR6 if s.family == socket.AF_INET6 else _MDNS_ADDR
                    elif not can_send_to(s, addr):
                        continue
                    else:
                        real_addr = addr
                    bytes_sent = s.sendto(packet, 0, (real_addr, port))
                except OSError as exc:
                    if exc.errno == errno.ENETUNREACH and s.family == socket.AF_INET6:
                        # with IPv6 we don't have a reliable way to determine if an interface actually has
                        # IPV6 support, so we have to try and ignore errors.
                        continue
                    # on send errors, log the exception and keep going
                    self.log_exception_warning('Error sending through socket %d', s.fileno())
                except Exception:  # pylint: disable=broad-except  # TODO stop catching all Exceptions
                    # on send errors, log the exception and keep going
                    self.log_exception_warning('Error sending through socket %d', s.fileno())
                else:
                    if bytes_sent != len(packet):
                        self.log_warning_once('!!! sent %d of %d bytes to %r' % (bytes_sent, len(packet), s))

    def close(self) -> None:
        """Ends the background threads, and prevent this instance from
        servicing further queries."""
        if self._GLOBAL_DONE:
            return
        # remove service listeners
        self.remove_all_service_listeners()
        self.unregister_all_services()
        self._GLOBAL_DONE = True

        # shutdown recv socket and thread
        if not self.unicast:
            self.engine.del_reader(cast(socket.socket, self._listen_socket))
            cast(socket.socket, self._listen_socket).close()
        if self.multi_socket:
            for s in self._respond_sockets:
                self.engine.del_reader(s)
        self.engine.join()
        # shutdown the rest
        self.notify_all()
        for s in self._respond_sockets:
            s.close()

    def __enter__(self) -> 'Zeroconf':
        return self

    def __exit__(  # pylint: disable=useless-return
        self,
        exc_type: Optional[Type[BaseException]],
        exc_val: Optional[BaseException],
        exc_tb: Optional[TracebackType],
    ) -> Optional[bool]:
        self.close()
        return None
