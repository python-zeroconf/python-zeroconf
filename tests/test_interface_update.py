"""Unit tests for runtime interface rescanning (async_update_interfaces)."""

from __future__ import annotations

import asyncio
import logging
import socket
from typing import cast
from unittest.mock import AsyncMock, Mock, patch

import pytest

from zeroconf import IPVersion, ServiceInfo, Zeroconf, _engine, _listener
from zeroconf._engine import _interface_key, _listen_socket_supports
from zeroconf._transport import _strip_zone, _WrappedTransport, make_wrapped_transport
from zeroconf.asyncio import AsyncZeroconf


def _make_wrapped(
    sock_name: tuple,
    is_ipv6: bool = False,
    transport: object | None = None,
    multicast_index: int = 0,
) -> _WrappedTransport:
    """Build a _WrappedTransport with mocked socket/transport for diff tests."""
    return _WrappedTransport(
        transport=cast("asyncio.DatagramTransport", transport or Mock()),
        is_ipv6=is_ipv6,
        sock=cast("socket.socket", Mock()),
        fileno=0,
        sock_name=sock_name,
        multicast_index=multicast_index,
    )


def test_strip_zone() -> None:
    assert _strip_zone("fe80::1%eth0") == "fe80::1"
    assert _strip_zone("192.168.1.5") == "192.168.1.5"


def test_interface_key() -> None:
    assert _interface_key("192.168.1.5") == ("192.168.1.5", 0)
    assert _interface_key((("fe80::1%eth0", 0, 7), 2)) == ("fe80::1", 7)
    # The same link-local address on two interfaces must not collapse to one key.
    assert _interface_key((("fe80::1", 0, 2), 2)) != _interface_key((("fe80::1", 0, 3), 3))


def test_wrapped_interface_key() -> None:
    assert _make_wrapped(("192.168.1.5", 5353)).interface_key == ("192.168.1.5", 0)
    assert _make_wrapped(("fe80::1%eth0", 5353, 0, 7), True).interface_key == ("fe80::1", 7)
    # A short sock_name (no scope_id) falls back to interface index 0.
    assert _make_wrapped(("fe80::1", 5353), True).interface_key == ("fe80::1", 0)


def test_wrapped_multicast_interface() -> None:
    assert _make_wrapped(("192.168.1.5", 5353)).multicast_interface == "192.168.1.5"
    # IPv6 leave carries the join index (IPV6_MULTICAST_IF), not the bound
    # scope_id (here sock_name scope_id 5 differs from multicast_index 9).
    wrapped = _make_wrapped(("fe80::1", 5353, 0, 5), is_ipv6=True, multicast_index=9)
    assert wrapped.multicast_interface == (("fe80::1", 0, 0), 9)


def test_make_wrapped_transport_reads_v6_multicast_index() -> None:
    """make_wrapped_transport reads IPV6_MULTICAST_IF as the v6 join index."""
    sock = Mock()
    sock.family = socket.AF_INET6
    sock.fileno.return_value = 0
    sock.getsockname.return_value = ("fe80::1", 5353, 0, 0)
    sock.getsockopt.return_value = 5
    transport = Mock()
    transport.get_extra_info.return_value = sock
    wrapped = make_wrapped_transport(transport)
    assert wrapped.is_ipv6 is True
    assert wrapped.multicast_index == 5
    sock.getsockopt.assert_called_once_with(socket.IPPROTO_IPV6, socket.IPV6_MULTICAST_IF)


def test_make_wrapped_transport_unreadable_multicast_index() -> None:
    """A socket that rejects reading IPV6_MULTICAST_IF falls back to index 0."""
    sock = Mock()
    sock.family = socket.AF_INET6
    sock.fileno.return_value = 0
    sock.getsockname.return_value = ("fe80::1", 5353, 0, 0)
    sock.getsockopt.side_effect = OSError
    transport = Mock()
    transport.get_extra_info.return_value = sock
    # Windows: expected (WSAEINVAL), silent fallback to the default index.
    with patch("zeroconf._transport.sys.platform", "win32"):
        assert make_wrapped_transport(transport).multicast_index == 0
    # Other platforms: the read does not fail there, so an error is re-raised.
    with patch("zeroconf._transport.sys.platform", "linux"), pytest.raises(OSError):
        make_wrapped_transport(transport)


def test_listen_socket_supports_family() -> None:
    """A desired interface is only supported by a listen socket of a compatible family."""
    v4_sock = Mock()
    v4_sock.family = socket.AF_INET
    v6_sock = Mock()
    v6_sock.family = socket.AF_INET6
    v6_interface = (("fe80::1", 0, 0), 1)

    assert _listen_socket_supports(v4_sock, "1.2.3.4") is True
    assert _listen_socket_supports(v4_sock, v6_interface) is False
    assert _listen_socket_supports(v6_sock, v6_interface) is True
    # IPv4 on an AF_INET6 socket depends on whether it is dual-stack.
    v6_sock.getsockopt.return_value = 0  # IPV6_V6ONLY off -> dual-stack
    assert _listen_socket_supports(v6_sock, "1.2.3.4") is True
    v6_sock.getsockopt.return_value = 1  # IPV6_V6ONLY on -> v6-only
    assert _listen_socket_supports(v6_sock, "1.2.3.4") is False
    # An unreadable option (some platforms) is treated as supported so it
    # can't drive a rebuild loop.
    v6_sock.getsockopt.side_effect = OSError
    assert _listen_socket_supports(v6_sock, "1.2.3.4") is True


@pytest.mark.asyncio
async def test_update_interfaces_noop(aiozc_loopback: AsyncZeroconf) -> None:
    """Re-scanning the same interface set leaves the engine lists unchanged."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    engine = zc.engine
    before = (len(engine.senders), len(engine.readers), len(engine.protocols))
    await aiozc_loopback.async_update_interfaces(["127.0.0.1"])
    assert (len(engine.senders), len(engine.readers), len(engine.protocols)) == before


@pytest.mark.asyncio
async def test_update_interfaces_defaults_to_stored_choice(aiozc_loopback: AsyncZeroconf) -> None:
    """Calling without an argument reuses the interface choice from construction."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    engine = zc.engine
    before = (len(engine.senders), len(engine.readers), len(engine.protocols))
    await aiozc_loopback.async_update_interfaces()
    assert (len(engine.senders), len(engine.readers), len(engine.protocols)) == before


@pytest.mark.asyncio
async def test_update_interfaces_accepts_ip_version_and_apple_p2p(aiozc_loopback: AsyncZeroconf) -> None:
    """ip_version and apple_p2p overrides are stored for the rescan."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    await aiozc_loopback.async_update_interfaces(["127.0.0.1"], ip_version=IPVersion.V4Only, apple_p2p=False)
    assert zc._ip_version is IPVersion.V4Only
    assert zc._apple_p2p is False


@pytest.mark.asyncio
async def test_update_interfaces_removes_and_readds(aiozc_loopback: AsyncZeroconf) -> None:
    """A gone interface drops its sender; a returning interface re-adds it."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    engine = zc.engine
    listen_reader_count = len(engine.readers) - len(engine.senders)

    await aiozc_loopback.async_update_interfaces([])
    await asyncio.sleep(0)
    assert engine.senders == []
    # The shared listen socket is never torn down.
    assert len(engine.readers) == listen_reader_count

    await aiozc_loopback.async_update_interfaces(["127.0.0.1"])
    await asyncio.sleep(0)
    assert len(engine.senders) == 1


@pytest.mark.asyncio
async def test_update_interfaces_keeps_unchanged_sender_untouched(aiozc_loopback: AsyncZeroconf) -> None:
    """An unchanged interface keeps its exact transport; only the gone interface is torn down."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    engine = zc.engine
    kept = engine.senders[0]
    kept_transport = kept.transport

    # Inject a sender for an interface that is absent from the new set.
    gone_transport = Mock()
    gone = _make_wrapped(("10.0.0.5", 5353), transport=gone_transport)
    engine.senders.append(gone)

    with patch.object(_engine, "drop_multicast_member"):
        await aiozc_loopback.async_update_interfaces(["127.0.0.1"])
    await asyncio.sleep(0)

    # The unchanged 127.0.0.1 sender is the same object, never recreated.
    assert engine.senders == [kept]
    assert engine.senders[0].transport is kept_transport
    # The gone interface's transport was closed exactly once.
    gone_transport.close.assert_called_once()


@pytest.mark.asyncio
async def test_update_interfaces_cancels_removed_listener_timers(aiozc_loopback: AsyncZeroconf) -> None:
    """Removing an interface cancels its listener's pending TC-reassembly timers."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    engine = zc.engine
    sender = engine.senders[0]
    protocol = next(
        p for p in engine.protocols if p.transport is not None and p.transport.transport is sender.transport
    )
    timer = Mock()
    protocol._timers["1.2.3.4"] = timer
    protocol._deferred["1.2.3.4"] = []
    protocol._deferred_deadlines["1.2.3.4"] = 0.0

    await aiozc_loopback.async_update_interfaces([])
    await asyncio.sleep(0)

    timer.cancel.assert_called_once()
    assert protocol._timers == {}
    assert protocol._deferred == {}


@pytest.mark.asyncio
async def test_close_sender_keeps_protocol_without_transport(aiozc_loopback: AsyncZeroconf) -> None:
    """A protocol that never bound a transport is left in place when a sender is closed."""
    engine = aiozc_loopback.zeroconf.engine
    await aiozc_loopback.zeroconf.async_wait_for_start()
    sender = engine.senders[0]
    orphan = _listener.AsyncListener(aiozc_loopback.zeroconf)
    assert orphan.transport is None
    engine.protocols.append(orphan)

    with patch.object(_engine, "drop_multicast_member"):
        engine._async_close_sender(sender, None)

    assert orphan in engine.protocols


@pytest.mark.asyncio
async def test_update_interfaces_reconciles_mixed_set(aiozc_loopback: AsyncZeroconf) -> None:
    """One rescan keeps unchanged, drops gone, adds new across v4 and link-local v6.

    Drives the engine diff directly over a controlled sender set (no real
    sockets) so the (address, scope_id) keying is exercised end to end,
    including two interfaces sharing fe80::1 distinguished only by scope.
    """
    engine = aiozc_loopback.zeroconf.engine
    await aiozc_loopback.zeroconf.async_wait_for_start()

    keep_v4 = _make_wrapped(("192.168.1.5", 5353))
    drop_v4 = _make_wrapped(("10.0.0.9", 5353))
    keep_v6 = _make_wrapped(("fe80::1", 5353, 0, 2), is_ipv6=True, multicast_index=2)
    drop_v6 = _make_wrapped(("fe80::1", 5353, 0, 3), is_ipv6=True, multicast_index=3)
    engine.senders = [keep_v4, drop_v4, keep_v6, drop_v6]

    # Keep 192.168.1.5 and fe80::1%2; drop 10.0.0.9 and fe80::1%3; add 192.168.1.9.
    desired = ["192.168.1.5", "192.168.1.9", (("fe80::1", 0, 2), 2)]
    added_sockets: list = []

    def _fake_wrap(sock: object, is_sender: bool) -> _WrappedTransport:
        added_sockets.append(sock)
        wrapped = _make_wrapped(("added", 0))
        engine.senders.append(wrapped)
        return wrapped

    with (
        patch.object(_engine, "normalize_interface_choice", return_value=desired),
        # This test exercises the diff over a contrived sender set, not the
        # listen-socket rebuild, so treat every family as supported.
        patch.object(_engine, "_listen_socket_supports", return_value=True),
        patch.object(_engine, "add_interface", return_value=Mock()),
        patch.object(_engine, "drop_multicast_member") as mock_drop,
        patch.object(_engine.AsyncEngine, "_async_wrap_socket", new=AsyncMock(side_effect=_fake_wrap)),
    ):
        added = await engine.async_update_interfaces(["unused"], IPVersion.All, False)

    assert added is True
    # Unchanged senders are the same objects; gone ones are removed.
    assert keep_v4 in engine.senders
    assert keep_v6 in engine.senders
    assert drop_v4 not in engine.senders
    assert drop_v6 not in engine.senders
    # Exactly one brand-new interface was added.
    assert len(added_sockets) == 1
    # Each gone interface left its group with its own representation; the
    # scope-3 v6 is dropped while the scope-2 v6 with the same address is kept.
    dropped = {call.args[1] for call in mock_drop.call_args_list}
    assert dropped == {"10.0.0.9", (("fe80::1", 0, 0), 3)}


@pytest.mark.asyncio
async def test_update_interfaces_reannounces_services_on_add(aiozc_loopback: AsyncZeroconf) -> None:
    """Existing registrations are re-announced when a new sender appears."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    info = ServiceInfo(
        "_test._tcp.local.",
        "Test._test._tcp.local.",
        addresses=[b"\x7f\x00\x00\x01"],
        port=80,
        server="test.local.",
    )
    await aiozc_loopback.async_register_service(info)
    # Drop the sender so the next rescan genuinely adds one back.
    await aiozc_loopback.async_update_interfaces([])
    await asyncio.sleep(0)

    with patch.object(zc, "_async_broadcast_service", new_callable=AsyncMock) as mock_broadcast:
        await aiozc_loopback.async_update_interfaces(["127.0.0.1"])
        await asyncio.sleep(0)

    assert mock_broadcast.call_count == 1
    assert mock_broadcast.call_args.args[0] is info


@pytest.mark.asyncio
async def test_update_interfaces_noop_does_not_reannounce(aiozc_loopback: AsyncZeroconf) -> None:
    """An unchanged interface set neither touches sockets nor re-announces."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    engine = zc.engine
    info = ServiceInfo(
        "_test._tcp.local.",
        "Test._test._tcp.local.",
        addresses=[b"\x7f\x00\x00\x01"],
        port=80,
        server="test.local.",
    )
    await aiozc_loopback.async_register_service(info)
    before = (len(engine.senders), len(engine.readers), len(engine.protocols))

    with patch.object(zc, "_async_broadcast_service", new_callable=AsyncMock) as mock_broadcast:
        await aiozc_loopback.async_update_interfaces(["127.0.0.1"])
        await asyncio.sleep(0)

    mock_broadcast.assert_not_called()
    assert (len(engine.senders), len(engine.readers), len(engine.protocols)) == before


@pytest.mark.asyncio
async def test_update_interfaces_logs_reannounce_errors(
    aiozc_loopback: AsyncZeroconf, caplog: pytest.LogCaptureFixture
) -> None:
    """A re-announce failure is logged and does not propagate out of the rescan."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    info = ServiceInfo(
        "_test._tcp.local.",
        "Test._test._tcp.local.",
        addresses=[b"\x7f\x00\x00\x01"],
        port=80,
        server="test.local.",
    )
    await aiozc_loopback.async_register_service(info)
    await aiozc_loopback.async_update_interfaces([])
    await asyncio.sleep(0)

    with (
        patch.object(zc, "_async_broadcast_service", new_callable=AsyncMock, side_effect=ValueError("boom")),
        caplog.at_level(logging.WARNING),
    ):
        await aiozc_loopback.async_update_interfaces(["127.0.0.1"])
        await asyncio.sleep(0)

    assert "Error re-announcing service after interface update" in caplog.text


@pytest.mark.asyncio
async def test_update_interfaces_reannounces_all_services_one_failing(
    aiozc_loopback: AsyncZeroconf, caplog: pytest.LogCaptureFixture
) -> None:
    """Every registration is re-announced on add; one failing does not stop the rest."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    infos = [
        ServiceInfo(
            "_test._tcp.local.",
            f"T{n}._test._tcp.local.",
            addresses=[b"\x7f\x00\x00\x01"],
            port=80 + n,
            server=f"t{n}.local.",
        )
        for n in range(2)
    ]
    for info in infos:
        await aiozc_loopback.async_register_service(info)
    await aiozc_loopback.async_update_interfaces([])
    await asyncio.sleep(0)

    async def broadcast(info: ServiceInfo, *args: object) -> None:
        if info is infos[0]:
            raise ValueError("boom")

    with (
        patch.object(zc, "_async_broadcast_service", new_callable=AsyncMock, side_effect=broadcast) as mock,
        caplog.at_level(logging.WARNING),
    ):
        await aiozc_loopback.async_update_interfaces(["127.0.0.1"])
        await asyncio.sleep(0)

    # Both services were attempted (the gather fans out over all registrations)
    # and the second still ran despite the first raising.
    announced = {call.args[0] for call in mock.call_args_list}
    assert announced == set(infos)
    assert "Error re-announcing service after interface update" in caplog.text


@pytest.mark.asyncio
async def test_update_interfaces_ip_change_in_one_rescan(aiozc_loopback: AsyncZeroconf) -> None:
    """An interface whose address changes is removed and re-added in a single rescan."""
    engine = aiozc_loopback.zeroconf.engine
    await aiozc_loopback.zeroconf.async_wait_for_start()
    old_transport = Mock()
    old = _make_wrapped(("10.0.0.5", 5353), transport=old_transport)
    engine.senders = [old]

    async def fake_wrap(sock: object, is_sender: bool) -> _WrappedTransport:
        wrapped = _make_wrapped(("10.0.0.9", 5353), transport=Mock())
        (engine.senders if is_sender else engine.readers).append(wrapped)
        return wrapped

    with (
        patch.object(_engine, "normalize_interface_choice", return_value=["10.0.0.9"]),
        patch.object(_engine, "_listen_socket_supports", return_value=True),
        patch.object(_engine, "add_interface", return_value=Mock()),
        patch.object(_engine, "drop_multicast_member") as mock_drop,
        patch.object(_engine.AsyncEngine, "_async_wrap_socket", new=AsyncMock(side_effect=fake_wrap)),
    ):
        added = await engine.async_update_interfaces(["unused"], IPVersion.All, False)

    assert added is True
    # The old address left its group and was closed; exactly the new one remains.
    assert {call.args[1] for call in mock_drop.call_args_list} == {"10.0.0.5"}
    old_transport.close.assert_called_once()
    assert old not in engine.senders
    assert len(engine.senders) == 1
    assert engine.senders[0].interface_key == ("10.0.0.9", 0)


@pytest.mark.asyncio
async def test_update_interfaces_add_failure_adds_no_sender(aiozc_loopback: AsyncZeroconf) -> None:
    """An interface that fails to come up adds no responder socket."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    engine = zc.engine
    await aiozc_loopback.async_update_interfaces([])
    await asyncio.sleep(0)

    with patch.object(_engine, "add_interface", return_value=None):
        await aiozc_loopback.async_update_interfaces(["127.0.0.1"])
    assert engine.senders == []


@pytest.mark.asyncio
async def test_update_interfaces_rolls_back_membership_on_wrap_failure(
    aiozc_loopback: AsyncZeroconf,
) -> None:
    """If endpoint creation raises, the interface's join and socket are rolled back."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    await aiozc_loopback.async_update_interfaces([])
    await asyncio.sleep(0)
    assert zc._interfaces == []

    fake_socket = Mock()
    with (
        patch.object(_engine, "add_interface", return_value=fake_socket),
        patch.object(_engine, "drop_multicast_member") as mock_drop,
        patch.object(_engine.AsyncEngine, "_async_wrap_socket", new=AsyncMock(side_effect=OSError("boom"))),
        pytest.raises(OSError),
    ):
        await aiozc_loopback.async_update_interfaces(["127.0.0.1"])

    # The just-joined membership was dropped, the socket closed, and the
    # failed reconcile left the retained config unchanged.
    mock_drop.assert_called_once()
    fake_socket.close.assert_called_once()
    assert zc._interfaces == []


@pytest.mark.asyncio
async def test_add_interface_rollback_without_listen_socket(aiozc_loopback: AsyncZeroconf) -> None:
    """A wrap failure with no listen socket (unicast) closes the socket and drops no membership."""
    engine = aiozc_loopback.zeroconf.engine
    await aiozc_loopback.zeroconf.async_wait_for_start()

    fake_socket = Mock()
    with (
        patch.object(_engine, "add_interface", return_value=fake_socket),
        patch.object(_engine, "drop_multicast_member") as mock_drop,
        patch.object(_engine.AsyncEngine, "_async_wrap_socket", new=AsyncMock(side_effect=OSError("boom"))),
        pytest.raises(OSError),
    ):
        await engine._async_add_interface("127.0.0.1", None, False)

    fake_socket.close.assert_called_once()
    mock_drop.assert_not_called()


@pytest.mark.asyncio
async def test_update_interfaces_keeps_dual_use_listen_socket(aiozc_loopback: AsyncZeroconf) -> None:
    """A dual-use sender (the listen socket itself) is never torn down on rescan."""
    engine = aiozc_loopback.zeroconf.engine
    await aiozc_loopback.zeroconf.async_wait_for_start()
    listen = engine._listen_transport
    assert listen is not None
    # Simulate a Default single-family instance: the listen socket is the sole sender.
    engine.senders = [listen]
    await engine.async_update_interfaces([], IPVersion.V4Only, False)
    assert engine.senders == [listen]


@pytest.mark.asyncio
async def test_update_interfaces_default_to_explicit_reconciles(aiozc_loopback: AsyncZeroconf) -> None:
    """Moving a dual-use instance to an explicit set demotes its socket and rebuilds clean."""
    engine = aiozc_loopback.zeroconf.engine
    await aiozc_loopback.zeroconf.async_wait_for_start()
    listen = engine._listen_transport
    assert listen is not None
    old_underlying = listen.transport
    # Simulate a Default single-family instance: the listen socket is the sole sender.
    engine.senders = [listen]
    new_listen_sock = Mock()
    new_listen_sock.family = socket.AF_INET

    async def fake_wrap(sock: object, is_sender: bool) -> _WrappedTransport:
        wrapped = _make_wrapped(("wrapped", 0), transport=Mock())
        (engine.senders if is_sender else engine.readers).append(wrapped)
        return wrapped

    with (
        patch.object(_engine, "normalize_interface_choice", return_value=["192.168.1.5"]),
        patch.object(_engine, "new_listen_socket", return_value=new_listen_sock) as mock_new_listen,
        patch.object(_engine, "add_interface", return_value=Mock()),
        patch.object(_engine, "drop_multicast_member"),
        patch.object(_engine.AsyncEngine, "_async_wrap_socket", new=AsyncMock(side_effect=fake_wrap)),
    ):
        added = await engine.async_update_interfaces(["unused"], IPVersion.V4Only, False)

    # The dual-use socket is rebuilt as a pure listener (demoted and closed),
    # a fresh listener replaces it, and the explicit interface gains a responder.
    assert added is True
    mock_new_listen.assert_called_once()
    assert engine._listen_transport is not listen
    assert listen not in engine.senders
    assert listen not in engine.readers
    assert old_underlying.is_closing()
    # One brand-new responder (for 192.168.1.5) is the only sender now.
    assert len(engine.senders) == 1
    assert engine.senders[0] is not listen


@pytest.mark.asyncio
async def test_update_interfaces_default_to_explicit_real(aiozc_loopback: AsyncZeroconf) -> None:
    """A real dual-use socket with an overlapping membership reconciles without EADDRINUSE."""
    engine = aiozc_loopback.zeroconf.engine
    await aiozc_loopback.zeroconf.async_wait_for_start()
    listen = engine._listen_transport
    assert listen is not None
    assert listen.sock.family == socket.AF_INET
    old_underlying = listen.transport
    # Simulate a Default dual-use instance whose listen socket already joined
    # the loopback group, so a naive demote-and-rejoin would hit EADDRINUSE.
    _engine.add_multicast_member(listen.sock, "127.0.0.1")
    engine.senders = [listen]

    with patch.object(_engine, "normalize_interface_choice", return_value=["127.0.0.1"]):
        added = await engine.async_update_interfaces(["unused"], IPVersion.V4Only, False)

    assert added is True
    new_listen = engine._listen_transport
    assert new_listen is not None
    assert new_listen is not listen
    assert new_listen.sock.family == socket.AF_INET
    assert old_underlying.is_closing()
    # The overlapping interface got a real responder on the fresh listen socket.
    assert len(engine.senders) == 1
    assert engine.senders[0] is not listen


@pytest.mark.asyncio
async def test_update_interfaces_does_not_rebuild_when_family_supported(
    aiozc_loopback: AsyncZeroconf,
) -> None:
    """Same-family rescans (and All/dual-stack) never rebuild the listen socket."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    listen = zc.engine._listen_transport
    with patch.object(_engine, "new_listen_socket") as mock_new_listen:
        await aiozc_loopback.async_update_interfaces(["127.0.0.1"])
        await aiozc_loopback.async_update_interfaces([])
        await asyncio.sleep(0)
        await aiozc_loopback.async_update_interfaces(["127.0.0.1"])
        await asyncio.sleep(0)
    mock_new_listen.assert_not_called()
    assert zc.engine._listen_transport is listen


@pytest.mark.asyncio
async def test_update_interfaces_rebuild_rejoins_kept_interfaces(aiozc_loopback: AsyncZeroconf) -> None:
    """On a family-change rebuild, interfaces that stay are re-joined on the new listen socket."""
    engine = aiozc_loopback.zeroconf.engine
    await aiozc_loopback.zeroconf.async_wait_for_start()

    # Keep the existing IPv4 interface and add an IPv6 one (which the IPv4
    # listen socket can't join, forcing a rebuild).
    v6 = (("fe80::1", 0, 0), 1)
    new_listen_sock = Mock()
    new_listen_sock.family = socket.AF_INET6

    async def fake_wrap(sock: object, is_sender: bool) -> _WrappedTransport:
        wrapped = _make_wrapped(("wrapped", 0), transport=Mock())
        (engine.senders if is_sender else engine.readers).append(wrapped)
        return wrapped

    with (
        patch.object(_engine, "normalize_interface_choice", return_value=["127.0.0.1", v6]),
        patch.object(_engine, "new_listen_socket", return_value=new_listen_sock),
        patch.object(_engine, "add_multicast_member", return_value=True) as mock_add,
        patch.object(_engine, "add_interface", return_value=Mock()),
        patch.object(_engine, "drop_multicast_member"),
        patch.object(_engine.AsyncEngine, "_async_wrap_socket", new=AsyncMock(side_effect=fake_wrap)),
    ):
        added = await engine.async_update_interfaces(["unused"], IPVersion.All, False)

    assert added is True
    # The kept IPv4 interface was re-joined on the new listen socket.
    assert any(
        call.args[0] is new_listen_sock and call.args[1] == "127.0.0.1" for call in mock_add.call_args_list
    )


@pytest.mark.asyncio
async def test_update_interfaces_rebuild_rejoin_failure_warns(
    aiozc_loopback: AsyncZeroconf, caplog: pytest.LogCaptureFixture
) -> None:
    """A staying interface that fails to re-join on the rebuilt listen socket warns."""
    engine = aiozc_loopback.zeroconf.engine
    await aiozc_loopback.zeroconf.async_wait_for_start()
    v6 = (("fe80::1", 0, 0), 1)
    new_listen_sock = Mock()
    new_listen_sock.family = socket.AF_INET6

    async def fake_wrap(sock: object, is_sender: bool) -> _WrappedTransport:
        wrapped = _make_wrapped(("wrapped", 0), transport=Mock())
        (engine.senders if is_sender else engine.readers).append(wrapped)
        return wrapped

    with (
        patch.object(_engine, "normalize_interface_choice", return_value=["127.0.0.1", v6]),
        patch.object(_engine, "new_listen_socket", return_value=new_listen_sock),
        patch.object(_engine, "add_multicast_member", return_value=False),
        patch.object(_engine, "add_interface", return_value=Mock()),
        patch.object(_engine, "drop_multicast_member"),
        patch.object(_engine.AsyncEngine, "_async_wrap_socket", new=AsyncMock(side_effect=fake_wrap)),
        caplog.at_level(logging.WARNING),
    ):
        await engine.async_update_interfaces(["unused"], IPVersion.All, False)

    assert "could not re-join the multicast group on the rebuilt listen socket" in caplog.text


@pytest.mark.asyncio
async def test_update_interfaces_rebuild_failure_raises(aiozc_loopback: AsyncZeroconf) -> None:
    """If the replacement listen socket can't be created, the rebuild raises."""
    engine = aiozc_loopback.zeroconf.engine
    await aiozc_loopback.zeroconf.async_wait_for_start()
    with (
        patch.object(_engine, "normalize_interface_choice", return_value=[(("fe80::1", 0, 0), 1)]),
        patch.object(_engine, "new_listen_socket", return_value=None),
        pytest.raises(RuntimeError, match="listen socket"),
    ):
        await engine.async_update_interfaces(["unused"], IPVersion.V6Only, False)


@pytest.mark.asyncio
async def test_update_interfaces_rebuild_closes_socket_on_wrap_failure(
    aiozc_loopback: AsyncZeroconf,
) -> None:
    """If wrapping the new listen socket fails, it is closed rather than leaked."""
    engine = aiozc_loopback.zeroconf.engine
    await aiozc_loopback.zeroconf.async_wait_for_start()
    old_listen = engine._listen_transport
    new_listen_sock = Mock()
    new_listen_sock.family = socket.AF_INET6

    with (
        patch.object(_engine, "normalize_interface_choice", return_value=[(("fe80::1", 0, 0), 1)]),
        patch.object(_engine, "new_listen_socket", return_value=new_listen_sock),
        patch.object(_engine, "add_multicast_member", return_value=True),
        patch.object(_engine.AsyncEngine, "_async_wrap_socket", new=AsyncMock(side_effect=OSError("boom"))),
        pytest.raises(OSError),
    ):
        await engine.async_update_interfaces(["unused"], IPVersion.V6Only, False)

    # The unadopted socket was closed, and the old listen socket is untouched.
    new_listen_sock.close.assert_called_once()
    assert engine._listen_transport is old_listen


@pytest.mark.asyncio
async def test_update_interfaces_rebuild_family_matches_desired_set(
    aiozc_loopback: AsyncZeroconf,
) -> None:
    """The rebuilt listen socket's family is derived from the desired set, not ip_version."""
    engine = aiozc_loopback.zeroconf.engine
    await aiozc_loopback.zeroconf.async_wait_for_start()
    new_listen_sock = Mock()
    new_listen_sock.family = socket.AF_INET

    async def fake_wrap(sock: object, is_sender: bool) -> _WrappedTransport:
        wrapped = _make_wrapped(("wrapped", 0), transport=Mock())
        (engine.senders if is_sender else engine.readers).append(wrapped)
        return wrapped

    with (
        patch.object(_engine, "normalize_interface_choice", return_value=["192.168.1.5"]),
        patch.object(_engine, "_listen_socket_supports", return_value=False),  # force a rebuild
        patch.object(_engine, "new_listen_socket", return_value=new_listen_sock) as mock_new_listen,
        patch.object(_engine, "add_multicast_member", return_value=True),
        patch.object(_engine, "add_interface", return_value=Mock()),
        patch.object(_engine, "drop_multicast_member"),
        patch.object(_engine.AsyncEngine, "_async_wrap_socket", new=AsyncMock(side_effect=fake_wrap)),
    ):
        # ip_version says V6Only, but the desired set is all IPv4, so the
        # rebuilt socket is IPv4 (covers the set; no immediate re-rebuild).
        await engine.async_update_interfaces(["unused"], IPVersion.V6Only, False)

    mock_new_listen.assert_called_once()
    assert mock_new_listen.call_args.args[0] is IPVersion.V4Only


@pytest.mark.asyncio
async def test_update_interfaces_rebuilds_real_listen_socket(aiozc_loopback: AsyncZeroconf) -> None:
    """End to end: a family change builds a real dual-stack listen socket and closes the old one."""
    engine = aiozc_loopback.zeroconf.engine
    await aiozc_loopback.zeroconf.async_wait_for_start()
    old_listen = engine._listen_transport
    assert old_listen is not None
    assert old_listen.sock.family == socket.AF_INET  # V4Only loopback instance
    old_underlying = old_listen.transport

    v6 = (("fe80::1", 0, 0), 1)
    # Real new_listen_socket + _async_wrap_socket run; only membership joins and
    # the (unbindable) v6 responder are stubbed so no real multicast is exercised.
    with (
        patch.object(_engine, "normalize_interface_choice", return_value=["127.0.0.1", v6]),
        patch.object(_engine, "add_multicast_member", return_value=True),
        patch.object(_engine, "add_interface", return_value=None),
    ):
        await engine.async_update_interfaces(["unused"], IPVersion.All, False)

    new_listen = engine._listen_transport
    assert new_listen is not None
    assert new_listen is not old_listen
    assert new_listen.sock.family == socket.AF_INET6  # rebuilt to a dual-stack socket
    # The old listen socket was closed and removed; no duplicate remains.
    assert old_underlying.is_closing()
    assert old_listen not in engine.readers
    assert sum(1 for r in engine.readers if r is new_listen) == 1


@pytest.mark.asyncio
async def test_close_sender_closes_transport_when_drop_raises(aiozc_loopback: AsyncZeroconf) -> None:
    """A non-benign group-leave error still releases the transport."""
    engine = aiozc_loopback.zeroconf.engine
    await aiozc_loopback.zeroconf.async_wait_for_start()
    gone_transport = Mock()
    gone = _make_wrapped(("10.0.0.5", 5353), transport=gone_transport)
    listen_socket = Mock()

    with (
        patch.object(_engine, "drop_multicast_member", side_effect=OSError("EPERM")),
        pytest.raises(OSError),
    ):
        engine._async_close_sender(gone, listen_socket)

    gone_transport.close.assert_called_once()


@pytest.mark.asyncio
async def test_update_interfaces_apple_p2p_non_darwin_raises(aiozc_loopback: AsyncZeroconf) -> None:
    """apple_p2p=True on a non-Apple platform raises, matching __init__."""
    await aiozc_loopback.zeroconf.async_wait_for_start()
    with (
        patch("zeroconf._core.sys.platform", "linux"),
        pytest.raises(RuntimeError, match="apple_p2p"),
    ):
        await aiozc_loopback.async_update_interfaces(apple_p2p=True)


@pytest.mark.asyncio
async def test_update_interfaces_copies_interface_list(aiozc_loopback: AsyncZeroconf) -> None:
    """A mutable interfaces list is copied so later mutation doesn't change retained config."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    ifaces = ["127.0.0.1"]
    await aiozc_loopback.async_update_interfaces(ifaces)
    ifaces.append("10.0.0.1")
    assert zc._interfaces == ["127.0.0.1"]


@pytest.mark.asyncio
async def test_update_interfaces_unicast_has_no_listen_socket() -> None:
    """In unicast mode there is no listen socket, so membership ops are skipped."""
    aiozc = AsyncZeroconf(interfaces=["127.0.0.1"], unicast=True)
    try:
        zc = aiozc.zeroconf
        await zc.async_wait_for_start()
        engine = zc.engine
        assert engine._listen_transport is None
        await aiozc.async_update_interfaces([])
        await asyncio.sleep(0)
        assert engine.senders == []
        # A None responder socket has no membership to roll back without a listen socket.
        with (
            patch.object(_engine, "add_interface", return_value=None),
            patch.object(_engine, "drop_multicast_member") as mock_drop,
        ):
            await aiozc.async_update_interfaces(["127.0.0.1"])
        assert engine.senders == []
        mock_drop.assert_not_called()
        await aiozc.async_update_interfaces(["127.0.0.1"])
        await asyncio.sleep(0)
        assert len(engine.senders) == 1
    finally:
        await aiozc.async_close()


@pytest.mark.asyncio
async def test_update_interfaces_serializes_concurrent_calls(aiozc_loopback: AsyncZeroconf) -> None:
    """Overlapping rescans are serialized so an interface is not added twice."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    engine = zc.engine
    await aiozc_loopback.async_update_interfaces([])
    await asyncio.sleep(0)
    assert engine.senders == []

    await asyncio.gather(
        aiozc_loopback.async_update_interfaces(["127.0.0.1"]),
        aiozc_loopback.async_update_interfaces(["127.0.0.1"]),
    )
    await asyncio.sleep(0)
    assert len(engine.senders) == 1


@pytest.mark.asyncio
async def test_update_interfaces_keeps_config_on_reconcile_failure(aiozc_loopback: AsyncZeroconf) -> None:
    """A failed engine reconcile leaves the retained interface config unchanged."""
    zc = aiozc_loopback.zeroconf
    await zc.async_wait_for_start()
    original_interfaces = zc._interfaces
    original_ip_version = zc._ip_version

    with (
        patch.object(_engine.AsyncEngine, "async_update_interfaces", new=AsyncMock(side_effect=OSError)),
        pytest.raises(OSError),
    ):
        await aiozc_loopback.async_update_interfaces(["10.0.0.1"], ip_version=IPVersion.All)

    assert zc._interfaces == original_interfaces
    assert zc._ip_version == original_ip_version


def test_sync_update_interfaces(zc_loopback: Zeroconf) -> None:
    """The sync wrapper drives a rescan through the loop without changing a stable set."""
    engine = zc_loopback.engine
    sender_count = len(engine.senders)
    zc_loopback.update_interfaces(["127.0.0.1"])
    assert len(engine.senders) == sender_count
