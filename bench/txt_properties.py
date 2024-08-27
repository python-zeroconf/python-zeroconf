import timeit

from zeroconf import ServiceInfo

info = ServiceInfo(
    "_test._tcp.local.",
    "test._test._tcp.local.",
    properties=(
        b"\x19md=AlexanderHomeAssistant\x06pv=1.0\x14id=59:8A:0B:74:65:1D\x05"
        b"c#=14\x04s#=1\x04ff=0\x04ci=2\x04sf=0\x0bsh=ccZLPA=="
    ),
)


def process_properties() -> None:
    info._properties = None
    info.properties  # noqa: B018


count = 100000
time = timeit.Timer(process_properties).timeit(count)
print(f"Processing {count} properties took {time} seconds")
