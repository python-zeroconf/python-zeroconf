
import cython

from ._protocol.incoming cimport DNSIncoming
from ._utils.time cimport current_time_millis, millis_to_seconds


cdef object log
cdef object logging_DEBUG


cdef cython.uint _MAX_MSG_ABSOLUTE

cdef class AsyncListener:

    cdef public object zc
    cdef public cython.bytes data
    cdef public cython.float last_time
    cdef public DNSIncoming last_message
    cdef public object transport
    cdef public object sock_description
    cdef public cython.dict _deferred
    cdef public cython.dict _timers

    @cython.locals(now=cython.float, msg=DNSIncoming)
    cpdef datagram_received(self, cython.bytes bytes, cython.tuple addrs)
