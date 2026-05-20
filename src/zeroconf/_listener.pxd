
import cython

from ._handlers.query_handler cimport QueryHandler
from ._handlers.record_manager cimport RecordManager
from ._protocol.incoming cimport DNSIncoming
from ._services.registry cimport ServiceRegistry
from ._utils.time cimport current_time_millis, millis_to_seconds


cdef object log
cdef object DEBUG_ENABLED
cdef bint TYPE_CHECKING

cdef cython.uint _MAX_MSG_ABSOLUTE
cdef cython.uint _RECENT_PACKETS_MAX


cdef class AsyncListener:

    cdef public object zc
    cdef ServiceRegistry _registry
    cdef RecordManager _record_manager
    cdef QueryHandler _query_handler
    cdef public object transport
    cdef public object sock_description
    cdef public cython.dict _deferred
    cdef public cython.dict _timers
    cdef public cython.dict _recent_packets

    @cython.locals(now=double, debug=cython.bint)
    cpdef datagram_received(self, cython.bytes bytes, cython.tuple addrs)

    @cython.locals(msg=DNSIncoming, recent_packets=cython.dict, recent=cython.tuple, was_present=cython.bint)
    cpdef _process_datagram_at_time(self, bint debug, cython.uint data_len, double now, bytes data, cython.tuple addrs)

    cdef _cancel_any_timers_for_addr(self, object addr)

    @cython.locals(incoming=DNSIncoming, deferred=list)
    cpdef handle_query_or_defer(
        self,
        DNSIncoming msg,
        object addr,
        object port,
        object transport,
        tuple v6_flow_scope
    )

    cpdef _respond_query(
        self,
        DNSIncoming msg,
        object addr,
        object port,
        object transport,
        tuple v6_flow_scope
    )
