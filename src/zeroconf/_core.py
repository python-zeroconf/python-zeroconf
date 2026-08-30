"""A pure python implementation of multicast DNS service discovery.

Licensed under LGPL-2.1-or-later; see COPYING for details. This file is
part of a continuously modified work; modification dates are recorded
in the project's git history.
"""

from __future__ import annotations

import asyncio
import logging
import random
import sys
import threading
from collections.abc import Awaitable
from types import TracebackType

from ._cache import DNSCache
from ._dns import DNSQuestion, DNSQuestionType
from ._engine import AsyncEngine
from ._exceptions import NonUniqueNameException, NotRunningException
from ._handlers.multicast_outgoing_queue import MulticastOutgoingQueue
from ._handlers.query_handler import QueryHandler
from ._handlers.record_manager import RecordManager
from ._history import QuestionHistory
from ._logger import QuietLogger, log
from ._protocol.outgoing import DNSOutgoing
from ._services import ServiceListener
from ._services.browser import ServiceBrowser
from ._services.info import (
    AsyncServiceInfo,
    ServiceInfo,
    instance_name_from_service_info,
)
from ._services.registry import ServiceRegistry
from ._transport import _WrappedTransport
from ._updates import RecordUpdateListener
from ._utils.asyncio import (
    _resolve_all_futures_to_none,
    await_awaitable,
    get_running_loop,
    run_coro_with_timeout,
    shutdown_loop,
    wait_for_future_set_or_timeout,
    wait_future_or_timeout,
)
from ._utils.name import service_type_name
from ._utils.net import (
    InterfaceChoice,
    InterfacesType,
    IPVersion,
    autodetect_ip_version,
    can_send_to,
    create_sockets,
)
from ._utils.time import current_time_millis, millis_to_seconds
from .const import (
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
    _ONE_SECOND,
    _REGISTER_TIME,
    _STARTUP_TIMEOUT,
    _TYPE_PTR,
    _UNREGISTER_TIME,
)

# The maximum amount of time to delay a multicast
# response in order to aggregate answers
_AGGREGATION_DELAY = 500  # ms
# The maximum amount of time to delay a multicast
# response in order to aggregate answers after
# it has already been delayed to protect the network
# from excessive traffic. We use a shorter time
# window here as we want to _try_ to answer all
# queries in under 1350ms while protecting
# the network from excessive traffic to ensure
# a service info request with two questions
# can be answered in the default timeout of
# 3000ms
_PROTECTED_AGGREGATION_DELAY = 200  # ms

_REGISTER_BROADCASTS = 3

# RFC 6762 §8.1 thundering-herd avoidance: wait a random
# 0-250ms before the first probe so simultaneously-started
# responders don't collide. We default to 150-250ms to
# preserve existing timing assumptions; tests on loopback
# may patch this lower via the `quick_timing` fixture.
_PROBE_RANDOM_DELAY_INTERVAL = (150, 250)  # ms


def async_send_with_transport(
    log_debug: bool,
    transport: _WrappedTransport,
    packet: bytes,
    packet_num: int,
    out: DNSOutgoing,
    addr: str | None,
    port: int,
    v6_flow_scope: tuple[()] | tuple[int, int] = (),
) -> None:
    ipv6_socket = transport.is_ipv6
    if addr is None:
        real_addr = _MDNS_ADDR6 if ipv6_socket else _MDNS_ADDR
    else:
        real_addr = addr
        if not can_send_to(ipv6_socket, real_addr):
            return
    if log_debug:
        log.debug(
            "Sending to (%s, %d) via [socket %s (%s)] (%d bytes #%d) %r as %r...",
            real_addr,
            port or _MDNS_PORT,
            transport.fileno,
            transport.sock_name,
            len(packet),
            packet_num + 1,
            out,
            packet,
        )
    # Get flowinfo and scopeid for the IPV6 socket to create a complete IPv6
    # address tuple: https://docs.python.org/3.6/library/socket.html#socket-families
    if ipv6_socket and not v6_flow_scope:
        _, _, sock_flowinfo, sock_scopeid = transport.sock_name
        v6_flow_scope = (sock_flowinfo, sock_scopeid)
    transport.transport.sendto(packet, (real_addr, port or _MDNS_PORT, *v6_flow_scope))


class Zeroconf(QuietLogger):
    """High level mDNS service discovery: register services, browse for
    them, and resolve their details on the local network."""

    def __init__(
        self,
        interfaces: InterfacesType = InterfaceChoice.All,
        unicast: bool = False,
        ip_version: IPVersion | None = None,
        apple_p2p: bool = False,
        use_asyncio: bool | None = None,
    ) -> None:
        """Open the multicast sockets and start serving on the chosen interfaces.

        :param interfaces: :class:`InterfaceChoice` or a list of IP addresses
            (IPv4 and IPv6) and interface indexes (IPv6 only).

            IPv6 notes for non-POSIX systems:
            * `InterfaceChoice.All` is an alias for `InterfaceChoice.Default`
              on Python versions before 3.8.

            Also listening on loopback (``::1``) doesn't work, use a real address.
        :param ip_version: IP versions to support. If `choice` is a list, the default is detected
            from it. Otherwise defaults to V4 only for backward compatibility.
        :param apple_p2p: use AWDL interface (only macOS)
        :param use_asyncio: explicitly control whether to attach to the running
            asyncio event loop (``True``) or run an internal thread with its
            own loop (``False``). ``None`` (default) keeps the historic
            behavior: attach if an event loop is running, otherwise start a
            thread. Set to ``False`` when running inside an environment that
            already has an event loop (e.g. Jupyter) but you want blocking
            semantics. ``True`` raises :class:`RuntimeError` immediately if no
            running event loop is found, instead of falling back to the thread.
        """
        if ip_version is None:
            ip_version = autodetect_ip_version(interfaces)

        self.done = False

        if apple_p2p and sys.platform != "darwin":
            raise RuntimeError("Option `apple_p2p` is not supported on non-Apple platforms.")

        if use_asyncio is True and get_running_loop() is None:
            raise RuntimeError("use_asyncio=True requires a running asyncio event loop")

        self.unicast = unicast
        self._use_asyncio = use_asyncio
        # Retained so async_update_interfaces can re-run create_sockets /
        # normalize_interface_choice against the live interface set later.
        # Copy a mutable list so later caller mutation can't change it.
        self._interfaces = list(interfaces) if isinstance(interfaces, list) else interfaces
        self._ip_version = ip_version
        self._apple_p2p = apple_p2p
        listen_socket, respond_sockets = create_sockets(interfaces, unicast, ip_version, apple_p2p=apple_p2p)
        log.debug("Listen socket %s, respond sockets %s", listen_socket, respond_sockets)

        self.engine = AsyncEngine(self, listen_socket, respond_sockets)

        self.browsers: dict[ServiceListener, ServiceBrowser] = {}
        self.registry = ServiceRegistry()
        self.cache = DNSCache()
        self.question_history = QuestionHistory()

        self.out_queue = MulticastOutgoingQueue(self, 0, _AGGREGATION_DELAY)
        self.out_delay_queue = MulticastOutgoingQueue(self, _ONE_SECOND, _PROTECTED_AGGREGATION_DELAY)

        self.query_handler = QueryHandler(self)
        self.record_manager = RecordManager(self)

        self._notify_futures: set[asyncio.Future] = set()
        # Serializes async_update_interfaces so overlapping calls (a bursty
        # adapter-change source) don't diff against a stale sender snapshot.
        self._interface_update_lock = asyncio.Lock()
        self.loop: asyncio.AbstractEventLoop | None = None
        self._loop_thread: threading.Thread | None = None

        self.start()

    def __enter__(self) -> Zeroconf:
        return self

    def __exit__(  # pylint: disable=useless-return
        self,
        exc_type: type[BaseException] | None,
        exc_val: BaseException | None,
        exc_tb: TracebackType | None,
    ) -> bool | None:
        self.close()
        return None

    def add_listener(
        self,
        listener: RecordUpdateListener,
        question: DNSQuestion | list[DNSQuestion] | None,
    ) -> None:
        """Subscribe a record update listener, optionally scoped to questions; threadsafe."""
        assert self.loop is not None
        self.loop.call_soon_threadsafe(self.record_manager.async_add_listener, listener, question)

    def add_service_listener(self, type_: str, listener: ServiceListener) -> None:
        """Browse for a type and deliver add, remove, and update callbacks to the listener."""
        self.remove_service_listener(listener)
        self.browsers[listener] = ServiceBrowser(self, type_, listener)

    def async_add_listener(
        self,
        listener: RecordUpdateListener,
        question: DNSQuestion | list[DNSQuestion] | None,
    ) -> None:
        """Subscribe a record update listener, optionally scoped to questions; event loop only."""
        self.record_manager.async_add_listener(listener, question)

    async def async_check_service(
        self,
        info: ServiceInfo,
        allow_name_change: bool,
        cooperating_responders: bool = False,
        strict: bool = True,
    ) -> None:
        """Probe the network for name uniqueness, renaming first when allowed."""
        instance_name = instance_name_from_service_info(info, strict=strict)
        if cooperating_responders:
            return

        # Wait a random amount of time up avoid collisions and avoid
        # a thundering herd when multiple services are started on the network
        await self.async_wait(random.randint(*_PROBE_RANDOM_DELAY_INTERVAL))  # noqa: S311

        next_instance_number = 2
        probes_sent = 0
        next_probe_at = current_time_millis()
        while probes_sent < _REGISTER_BROADCASTS:
            # check for a name conflict; a cache update during the wait below
            # wakes async_wait, so a conflicting response lands here promptly
            if self.cache.current_entry_with_name_and_alias(info.type, info.name):
                if not allow_name_change:
                    raise NonUniqueNameException

                # change the name and restart probing from zero
                info.name = f"{instance_name}-{next_instance_number}.{info.type}"
                next_instance_number += 1
                service_type_name(info.name, strict=strict)
                probes_sent = 0
                next_probe_at = current_time_millis()
                continue

            remaining = next_probe_at - current_time_millis()
            if remaining > 0:
                await self.async_wait(remaining)
                continue

            self.async_send(self.generate_service_query(info))
            probes_sent += 1
            next_probe_at += _CHECK_TIME

    async def async_get_service_info(
        self,
        type_: str,
        name: str,
        timeout: int = 3000,
        question_type: DNSQuestionType | None = None,
    ) -> AsyncServiceInfo | None:
        """Look up details for a service on the network from the event loop.

        Queries for the given fully qualified type and name, waiting up to
        timeout milliseconds, and returns a populated AsyncServiceInfo or
        None when nothing answered in time. question_type forces QM or QU
        questions instead of the automatic choice.
        """
        info = AsyncServiceInfo(type_, name)
        if await info.async_request(self, timeout, question_type):
            return info
        return None

    def async_notify_all(self) -> None:
        """Schedule an async_notify_all."""
        notify_futures = self._notify_futures
        if notify_futures:
            _resolve_all_futures_to_none(notify_futures)

    async def async_register_service(
        self,
        info: ServiceInfo,
        ttl: int | None = None,
        allow_name_change: bool = False,
        cooperating_responders: bool = False,
        strict: bool = True,
    ) -> Awaitable:
        """Announce a service on the network from the event loop.

        Returns an awaitable that completes once the announcements have
        been sent. Prefer setting TTLs on the ServiceInfo over the ttl
        argument.
        """
        if ttl is not None:
            # ttl argument is used to maintain backward compatibility
            # Setting TTLs via ServiceInfo is preferred
            info.host_ttl = ttl
            info.other_ttl = ttl

        info.set_server_if_missing()
        await self.async_wait_for_start()
        await self.async_check_service(info, allow_name_change, cooperating_responders, strict)
        self.registry.async_add(info)
        return asyncio.ensure_future(self._async_broadcast_service(info, _REGISTER_TIME, None))

    def async_remove_listener(self, listener: RecordUpdateListener) -> None:
        """Detach a record listener; event loop only, not threadsafe."""
        self.record_manager.async_remove_listener(listener)

    def async_send(
        self,
        out: DNSOutgoing,
        addr: str | None = None,
        port: int = _MDNS_PORT,
        v6_flow_scope: tuple[()] | tuple[int, int] = (),
        transport: _WrappedTransport | None = None,
    ) -> None:
        """Transmit a packet from the event loop."""
        if self.done:
            return

        # If no transport is specified, we send to all the ones
        # with the same address family
        transports = [transport] if transport else self.engine.senders
        log_debug = log.isEnabledFor(logging.DEBUG)

        for packet_num, packet in enumerate(out.packets()):
            if len(packet) > _MAX_MSG_ABSOLUTE:
                self.log_warning_once(
                    "Dropping %r over-sized packet (%d bytes) %r",
                    out,
                    len(packet),
                    packet,
                )
                return
            for send_transport in transports:
                async_send_with_transport(
                    log_debug,
                    send_transport,
                    packet,
                    packet_num,
                    out,
                    addr,
                    port,
                    v6_flow_scope,
                )

    async def async_unregister_all_services(self) -> None:
        """Send goodbye packets for every registered service and drop them all.

        Runs only at shutdown, so unlike the single service calls it
        returns nothing to await separately.
        """
        # Send Goodbye packets https://datatracker.ietf.org/doc/html/rfc6762#section-10.1
        out = self.generate_unregister_all_services()
        if not out:
            return
        for i in range(_REGISTER_BROADCASTS):
            if i != 0:
                await asyncio.sleep(millis_to_seconds(_UNREGISTER_TIME))
            self.async_send(out)

    async def async_unregister_service(self, info: ServiceInfo) -> Awaitable:
        """Withdraw a service from the event loop, broadcasting goodbyes."""
        info.set_server_if_missing()
        self.registry.async_remove(info)
        # If another server uses the same addresses, we do not want to send
        # goodbye packets for the address records

        assert info.server_key is not None
        entries = self.registry.async_get_infos_server(info.server_key)
        broadcast_addresses = not bool(entries)
        return asyncio.ensure_future(
            self._async_broadcast_service(info, _UNREGISTER_TIME, 0, broadcast_addresses)
        )

    async def async_update_interfaces(
        self,
        interfaces: InterfacesType | None = None,
        ip_version: IPVersion | None = None,
        apple_p2p: bool | None = None,
    ) -> None:
        """Rescan network interfaces and reconcile the sockets in use.

        Adds sockets for interfaces that appeared, drops sockets for
        interfaces that disappeared, and re-announces existing
        registrations when a new sender appeared. ``interfaces``,
        ``ip_version`` and ``apple_p2p`` each default to the value passed at
        construction; pass a new value to switch it. When the resulting
        interface set is unchanged this is a no-op (no sockets touched,
        nothing re-announced). The listen socket is rebuilt if the new set
        needs a different address family; unicast mode is fixed at
        construction. Concurrent calls are serialized. Bringing up interfaces
        is best-effort: a requested interface that fails to bind, or fails to
        re-join after a rebuild, is logged rather than raised, and likewise a
        registration that fails to re-announce is logged so one failure cannot
        block the others. Raises RuntimeError if apple_p2p is set on a non-Apple
        platform (input validation, matching the constructor).
        """
        # Resolve against the retained config but only commit it after the
        # engine reconcile succeeds, so a failed reconcile leaves the stored
        # config unchanged rather than recording a set that never fully bound
        # (a mid-reconcile failure may still have changed some sockets).
        interfaces = self._interfaces if interfaces is None else interfaces
        ip_version = self._ip_version if ip_version is None else ip_version
        apple_p2p = self._apple_p2p if apple_p2p is None else apple_p2p
        if apple_p2p and sys.platform != "darwin":
            raise RuntimeError("Option `apple_p2p` is not supported on non-Apple platforms.")
        await self.async_wait_for_start()
        # Only the reconcile mutates the sender set, so hold the lock for that
        # alone; the multi-second re-announce runs unlocked so a bursty
        # adapter-change source isn't blocked behind it.
        async with self._interface_update_lock:
            added = await self.engine.async_update_interfaces(interfaces, ip_version, apple_p2p)
            # Copy a mutable list so later caller mutation can't change the
            # retained configuration.
            self._interfaces = list(interfaces) if isinstance(interfaces, list) else interfaces
            self._ip_version = ip_version
            self._apple_p2p = apple_p2p
        if not added:
            return
        # Re-announce every registration; one broadcast failing must not mask
        # the rest, so collect exceptions and log them individually, naming the
        # service so a partial failure is actionable.
        infos = self.registry.async_get_service_infos()
        results = await asyncio.gather(
            *[self._async_broadcast_service(info, _REGISTER_TIME, None) for info in infos],
            return_exceptions=True,
        )
        for info, result in zip(infos, results, strict=True):
            if isinstance(result, Exception):
                log.warning("Error re-announcing %s after interface update: %s", info.name, result)
            elif isinstance(result, BaseException):
                # gather(return_exceptions=True) also captures BaseExceptions
                # such as CancelledError; don't swallow a cancellation/interrupt.
                raise result

    async def async_update_service(self, info: ServiceInfo) -> Awaitable:
        """Publish updated records for an already registered service.

        Returns an awaitable that completes once the rebroadcasts finish.
        """
        self.registry.async_update(info)
        return asyncio.ensure_future(self._async_broadcast_service(info, _REGISTER_TIME, None))

    async def async_wait(self, timeout: float) -> None:
        """Pause until notified or until timeout milliseconds pass."""
        loop = self.loop
        assert loop is not None
        await wait_for_future_set_or_timeout(loop, self._notify_futures, timeout)

    async def async_wait_for_start(self, timeout: float = _STARTUP_TIMEOUT) -> None:
        """Wait for start up for actions that require a running Zeroconf instance.

        Throws NotRunningException if the instance is not running or could
        not be started.
        """
        if self.done:  # If the instance was shutdown from under us, raise immediately
            raise NotRunningException
        assert self.engine.running_future is not None
        await wait_future_or_timeout(self.engine.running_future, timeout=timeout)
        if not self.started:
            raise NotRunningException

    def close(self) -> None:
        """Shut down the sockets and engine for good; safe to call repeatedly."""
        assert self.loop is not None
        if self.loop.is_running():
            if self.loop == get_running_loop():
                log.warning(
                    "unregister_all_services skipped as it does blocking i/o; use AsyncZeroconf with asyncio"
                )
            else:
                self.unregister_all_services()
        self._close()
        self.engine.close()
        self._shutdown_threads()

    def generate_service_broadcast(
        self,
        info: ServiceInfo,
        ttl: int | None,
        broadcast_addresses: bool = True,
    ) -> DNSOutgoing:
        """Generate a broadcast to announce a service."""
        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
        self._add_broadcast_answer(out, info, ttl, broadcast_addresses)
        return out

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

    def generate_unregister_all_services(self) -> DNSOutgoing | None:
        """Generate a DNSOutgoing goodbye for all services and remove them from the registry."""
        service_infos = self.registry.async_get_service_infos()
        if not service_infos:
            return None
        out = DNSOutgoing(_FLAGS_QR_RESPONSE | _FLAGS_AA)
        for info in service_infos:
            self._add_broadcast_answer(out, info, 0)
        self.registry.async_remove(service_infos)
        return out

    def get_service_info(
        self,
        type_: str,
        name: str,
        timeout: int = 3000,
        question_type: DNSQuestionType | None = None,
    ) -> ServiceInfo | None:
        """Look up details for a service on the network.

        Queries for the given fully qualified type and name, waiting up to
        timeout milliseconds, and returns a populated ServiceInfo or None
        when nothing answered in time. question_type forces QM or QU
        questions instead of the automatic choice.
        """
        info = ServiceInfo(type_, name)
        if info.request(self, timeout, question_type):
            return info
        return None

    @property
    def listeners(self) -> set[RecordUpdateListener]:
        return self.record_manager.listeners

    def notify_all(self) -> None:
        """Wake every waiter and fire the listeners, from any thread."""
        assert self.loop is not None
        self.loop.call_soon_threadsafe(self.async_notify_all)

    def register_service(
        self,
        info: ServiceInfo,
        ttl: int | None = None,
        allow_name_change: bool = False,
        cooperating_responders: bool = False,
        strict: bool = True,
    ) -> None:
        """Announce a service on the network.

        Probes for conflicts first; with allow_name_change the instance
        name is renamed until it is unique. May raise EventLoopBlocked
        when the event loop cannot complete the registration in time.
        """
        assert self.loop is not None
        run_coro_with_timeout(
            await_awaitable(
                self.async_register_service(info, ttl, allow_name_change, cooperating_responders, strict)
            ),
            self.loop,
            _REGISTER_TIME * _REGISTER_BROADCASTS,
        )

    def remove_all_service_listeners(self) -> None:
        """Stop the browsers behind every registered listener."""
        for listener in list(self.browsers):
            self.remove_service_listener(listener)

    def remove_listener(self, listener: RecordUpdateListener) -> None:
        """Detach a record listener from any thread."""
        assert self.loop is not None
        self.loop.call_soon_threadsafe(self.record_manager.async_remove_listener, listener)

    def remove_service_listener(self, listener: ServiceListener) -> None:
        """Stop the browser behind the given listener."""
        if listener in self.browsers:
            self.browsers[listener].cancel()
            del self.browsers[listener]

    def send(
        self,
        out: DNSOutgoing,
        addr: str | None = None,
        port: int = _MDNS_PORT,
        v6_flow_scope: tuple[()] | tuple[int, int] = (),
        transport: _WrappedTransport | None = None,
    ) -> None:
        """Queue a packet for transmission from any thread."""
        assert self.loop is not None
        self.loop.call_soon_threadsafe(self.async_send, out, addr, port, v6_flow_scope, transport)

    def start(self) -> None:
        """Start Zeroconf."""
        self.loop = None if self._use_asyncio is False else get_running_loop()
        if self.loop:
            self.engine.setup(self.loop, None)
            return
        self._start_thread()

    @property
    def started(self) -> bool:
        """Check if the instance has started."""
        running_future = self.engine.running_future
        return bool(
            not self.done
            and running_future
            and running_future.done()
            and not running_future.cancelled()
            and not running_future.exception()
            and running_future.result()
        )

    def unregister_all_services(self) -> None:
        """Send goodbye packets for every registered service and drop them all.

        May raise EventLoopBlocked when the event loop cannot finish the
        shutdown broadcasts in time.
        """
        assert self.loop is not None
        run_coro_with_timeout(
            self.async_unregister_all_services(),
            self.loop,
            _UNREGISTER_TIME * _REGISTER_BROADCASTS,
        )

    def unregister_service(self, info: ServiceInfo) -> None:
        """Withdraw a service by broadcasting goodbye records.

        May raise EventLoopBlocked when the event loop cannot finish the
        withdrawal in time.
        """
        assert self.loop is not None
        run_coro_with_timeout(
            self.async_unregister_service(info),
            self.loop,
            _UNREGISTER_TIME * _REGISTER_BROADCASTS,
        )

    def update_interfaces(
        self,
        interfaces: InterfacesType | None = None,
        ip_version: IPVersion | None = None,
        apple_p2p: bool | None = None,
    ) -> None:
        """Rescan network interfaces and reconcile the sockets in use.

        While it is not expected during normal operation,
        this function may raise EventLoopBlocked if the underlying
        call to `async_update_interfaces` cannot be completed. Raises
        RuntimeError if apple_p2p is set on a non-Apple platform.
        """
        assert self.loop is not None
        # Unlike register/update, the re-announce is awaited inline (to log
        # per-service failures), so the budget must cover the full announce
        # window ((_REGISTER_BROADCASTS - 1) * _REGISTER_TIME) plus the reconcile
        # and wait-for-start overhead; double the register budget for headroom.
        run_coro_with_timeout(
            self.async_update_interfaces(interfaces, ip_version, apple_p2p),
            self.loop,
            _REGISTER_TIME * _REGISTER_BROADCASTS * 2,
        )

    def update_service(self, info: ServiceInfo) -> None:
        """Publish updated records for an already registered service.

        May raise EventLoopBlocked when the event loop cannot complete
        the update in time.
        """
        assert self.loop is not None
        run_coro_with_timeout(
            await_awaitable(self.async_update_service(info)),
            self.loop,
            _REGISTER_TIME * _REGISTER_BROADCASTS,
        )

    def _add_broadcast_answer(  # pylint: disable=no-self-use
        self,
        out: DNSOutgoing,
        info: ServiceInfo,
        override_ttl: int | None,
        broadcast_addresses: bool = True,
    ) -> None:
        """Add answers to broadcast a service."""
        current_time_millis()
        other_ttl = None if override_ttl is None else override_ttl
        host_ttl = None if override_ttl is None else override_ttl
        out.add_answer_at_time(info.dns_pointer(override_ttl=other_ttl), 0)
        out.add_answer_at_time(info.dns_service(override_ttl=host_ttl), 0)
        out.add_answer_at_time(info.dns_text(override_ttl=other_ttl), 0)
        if broadcast_addresses:
            for record in info.get_address_and_nsec_records(override_ttl=host_ttl):
                out.add_answer_at_time(record, 0)

    async def _async_broadcast_service(
        self,
        info: ServiceInfo,
        interval: int,
        ttl: int | None,
        broadcast_addresses: bool = True,
    ) -> None:
        """Send a broadcasts to announce a service at intervals."""
        for i in range(_REGISTER_BROADCASTS):
            if i != 0:
                await asyncio.sleep(millis_to_seconds(interval))
            self.async_send(self.generate_service_broadcast(info, ttl, broadcast_addresses))

    async def _async_close(self) -> None:
        """Shut down for AsyncZeroconf; callers unregister services first."""
        self._close()
        await self.engine._async_close()  # pylint: disable=protected-access
        self._shutdown_threads()

    def _close(self) -> None:
        """Set global done and remove all service listeners."""
        if self.done:
            return
        self.remove_all_service_listeners()
        self.done = True

    def _shutdown_threads(self) -> None:
        """Shutdown any threads."""
        assert self.loop is not None
        if self.loop.is_closed():
            # close() is documented as idempotent — a second call after the
            # loop has been torn down must be a no-op rather than raising.
            return
        self.notify_all()
        if not self._loop_thread:
            return
        shutdown_loop(self.loop)
        self._loop_thread.join()
        self._loop_thread = None
        # The loop's selector (epoll FD on Linux) and self-pipe sockets stay
        # open until loop.close() is called. We own this loop because
        # _start_thread() created it, so close it here to avoid leaking
        # those file descriptors across Zeroconf() construct/close cycles.
        self.loop.close()

    def _start_thread(self) -> None:
        """Start a thread with a running event loop."""
        loop_thread_ready = threading.Event()

        def _run_loop() -> None:
            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.engine.setup(self.loop, loop_thread_ready)
            self.loop.run_forever()

        self._loop_thread = threading.Thread(target=_run_loop, daemon=True)
        self._loop_thread.start()
        loop_thread_ready.wait()
