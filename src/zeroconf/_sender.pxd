
import cython

from ._engine cimport AsyncEngine
from ._transport cimport _WrappedTransport
from ._protocol.outgoing import DNSOutgoing

cdef void async_send_with_transport(
    bint log_debug
    _WrappedTransport transport,
    bytes packet,
    int packet_num,
    DNSOutgoing out,
    str addr,
    int port,
    tuple v6_flow_scope
)

cdef class _ZeroconfSender:

    cdef public object zc
    cdef public object loop
    cdef public bint done
    cdef public AsyncEngine
