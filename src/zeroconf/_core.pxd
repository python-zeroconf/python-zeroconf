
import cython


cdef bint TYPE_CHECKING
cdef object _MDNS_ADDR6,_MDNS_ADDR


from ._cache cimport DNSCache
from ._handlers.multicast_outgoing_queue cimport MulticastOutgoingQueue
from ._handlers.query_handler cimport QueryHandler, QuestionAnswers
from ._history cimport QuestionHistory
from ._listener cimport AsyncListener
from ._protocol.incoming cimport DNSIncoming
from ._protocol.outgoing cimport DNSOutgoing
from ._services.registry cimport ServiceRegistry
from ._transport cimport _WrappedTransport
from ._updates cimport RecordUpdateListener


cdef void async_send_with_transport(
    bint log_debug,
    _WrappedTransport transport,
    object packet,
    object packet_num,
    DNSOutgoing out,
    object addr,
    object port,
    tuple v6_flow_scope
)

cdef class Zeroconf:

    cdef public bint done
    cdef public bint unicast
    cdef public object engine
    cdef public dict browsers
    cdef public ServiceRegistry registry
    cdef public DNSCache cache
    cdef public QuestionHistory question_history
    cdef public QueryHandler query_handler
    cdef public object record_manager
    cdef public set _notify_futures
    cdef public object loop
    cdef public object _loop_thread
    cdef public MulticastOutgoingQueue _out_queue
    cdef public MulticastOutgoingQueue _out_delay_queue

    cdef bint _debug_enabled(self)

    @cython.locals(first_packet=DNSIncoming)
    cpdef handle_assembled_query(
        self,
        list packets,
        object addr,
        object port,
        _WrappedTransport transport,
        tuple v6_flow_scope
    )

    @cython.locals(max_size="unsigned int")
    cpdef _async_send(
        self,
        DNSOutgoing out,
        object addr,
        object port,
        tuple v6_flow_scope,
        _WrappedTransport transport
    )
