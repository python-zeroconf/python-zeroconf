"""Benchmark for DNSOutgoing."""

from pytest_codspeed import BenchmarkFixture

from zeroconf._protocol.outgoing import State

from .helpers import generate_packets


def test_parse_outgoing_message(benchmark: BenchmarkFixture) -> None:
    out = generate_packets()

    @benchmark
    def make_outgoing_message() -> None:
        out.packets()
        out.state = State.init.value
        out.finished = False
        out._reset_for_next_packet()
