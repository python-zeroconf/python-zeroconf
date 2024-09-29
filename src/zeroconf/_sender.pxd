
import cython

from ._transport cimport _WrappedTransport
from ._protocol.outgoing cimport DNSOutgoing

cdef object can_send_to
cdef object _MDNS_PORT
cdef object _MDNS_ADDR6
cdef object _MDNS_ADDR
cdef unsigned int _MAX_MSG_ABSOLUTE

cdef void async_send_with_transport(
    bint log_debug,
    _WrappedTransport transport,
    bytes packet,
    object packet_num,
    DNSOutgoing out,
    str addr,
    object port,
    tuple v6_flow_scope
)

cdef class _ZeroconfSender:

    cdef public object zc
    cdef public object loop
    cdef public bint done
    cdef public object engine
