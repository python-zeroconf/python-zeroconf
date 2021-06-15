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
import platform
import select
import socket
import threading
from types import TracebackType  # noqa # used in type hints
from typing import Dict, List, Optional, Type, Union, cast

from ._cache import DNSCache
from ._dns import DNSIncoming, DNSOutgoing, DNSQuestion
from ._exceptions import NonUniqueNameException
from ._handlers import QueryHandler, RecordManager
from ._logger import QuietLogger, log
from ._services import (
    RecordUpdateListener,
    ServiceBrowser,
    ServiceInfo,
    ServiceListener,
    instance_name_from_service_info,
)
from ._services.registry import ServiceRegistry
from ._utils.name import service_type_name
from ._utils.net import (
    IPVersion,
    InterfaceChoice,
    InterfacesType,
    autodetect_ip_version,
    can_send_to,
    create_sockets,
)
from ._utils.time import current_time_millis, millis_to_seconds
from .const import (
    _CACHE_CLEANUP_INTERVAL,
    _CHECK_TIME,
    _CLASS_IN,
    _CLASS_UNIQUE,
    _FLAGS_AA,
    _FLAGS_QR_QUERY,
    _FLAGS_QR_RESPONSE,
    _MAX_MSG_ABSOLUTE,
    _MDNS_ADDR,
    _MDNS_ADDR6,
    _MDNS_PORT,
    _REGISTER_TIME,
    _TYPE_PTR,
    _UNREGISTER_TIME,
)


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

        elif not msg.is_query():
            self.zc.handle_response(msg)
            return

        self.zc.handle_query(msg, addr, port)


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
        self.cache = DNSCache()
        self.query_handler = QueryHandler(self.registry, self.cache)
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
        # https://datatracker.ietf.org/doc/html/rfc6762#section-8.1
        # Because of the mDNS multicast rate-limiting
        # rules, the probes SHOULD be sent as "QU" questions with the unicast-
        # response bit set, to allow a defending host to respond immediately
        # via unicast, instead of potentially having to wait before replying
        # via multicast.
        #
        # _CLASS_UNIQUE is the "QU" bit
        out.add_question(DNSQuestion(info.type, _TYPE_PTR, _CLASS_IN | _CLASS_UNIQUE))
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
        unicast_out, multicast_out = self.query_handler.response(msg, addr, port)
        if unicast_out and unicast_out.answers:
            self.send(unicast_out, addr, port)
        if multicast_out and multicast_out.answers:
            self.send(multicast_out, None, _MDNS_PORT)

    def send(self, out: DNSOutgoing, addr: Optional[str] = None, port: int = _MDNS_PORT) -> None:
        """Sends an outgoing packet."""
        for packet_num, packet in enumerate(out.packets()):
            if len(packet) > _MAX_MSG_ABSOLUTE:
                self.log_warning_once("Dropping %r over-sized packet (%d bytes) %r", out, len(packet), packet)
                return
            log.debug(
                'Sending to (%s, %d) (%d bytes #%d) %r as %r...',
                addr,
                port,
                len(packet),
                packet_num + 1,
                out,
                packet,
            )
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
