
import cython

from .._cache cimport DNSCache
from .._history cimport QuestionHistory
from .._protocol.outgoing cimport DNSOutgoing, DNSPointer, DNSQuestion, DNSRecord
from .._record_update cimport RecordUpdate
from .._updates cimport RecordUpdateListener
from .._utils.time cimport current_time_millis, millis_to_seconds
from . cimport Signal, SignalRegistrationInterface


cdef bint TYPE_CHECKING
cdef object cached_possible_types
cdef cython.uint _EXPIRE_REFRESH_TIME_PERCENT, _MAX_MSG_TYPICAL, _DNS_PACKET_HEADER_LEN
cdef cython.uint _TYPE_PTR
cdef object _CLASS_IN
cdef object SERVICE_STATE_CHANGE_ADDED, SERVICE_STATE_CHANGE_REMOVED, SERVICE_STATE_CHANGE_UPDATED
cdef cython.set _ADDRESS_RECORD_TYPES
cdef cython.uint STARTUP_QUERIES

cdef object QU_QUESTION

cdef object heappop, heappush

cdef class _ScheduledQuery:

    cdef public str name
    cdef public str type_
    cdef public bint cancelled
    cdef public double when_millis

cdef class _DNSPointerOutgoingBucket:

    cdef public double now_millis
    cdef public DNSOutgoing out
    cdef public cython.uint bytes

    cpdef add(self, cython.uint max_compressed_size, DNSQuestion question, cython.set answers)

@cython.locals(cache=DNSCache, question_history=QuestionHistory, record=DNSRecord, qu_question=bint)
cpdef list generate_service_query(
    object zc,
    double now_millis,
    set types_,
    bint multicast,
    object question_type
)

@cython.locals(answer=DNSPointer, query_buckets=list, question=DNSQuestion, max_compressed_size=cython.uint, max_bucket_size=cython.uint, query_bucket=_DNSPointerOutgoingBucket)
cdef _group_ptr_queries_with_known_answers(double now_millis, object multicast, cython.dict question_with_known_answers)

cdef class QueryScheduler:

    cdef _ServiceBrowserBase _browser
    cdef tuple _first_random_delay_interval
    cdef double _min_time_between_queries_millis
    cdef object _loop
    cdef unsigned int _startup_queries_sent
    cdef dict _next_scheduled_for_name
    cdef list _query_heap
    cdef object _next_run

    cpdef schedule(self, DNSPointer pointer)

    @cython.locals(scheduled=_ScheduledQuery)
    cpdef cancel(self, DNSPointer pointer)

    @cython.locals(current=_ScheduledQuery)
    cpdef reschedule(self, DNSPointer pointer)

    cpdef _process_startup_queries(self)

    @cython.locals(query=_ScheduledQuery, next_scheduled=_ScheduledQuery, next_when=double)
    cpdef _process_ready_types(self)

cdef class _ServiceBrowserBase(RecordUpdateListener):

    cdef public cython.set types
    cdef public object zc
    cdef DNSCache _cache
    cdef object _loop
    cdef public object addr
    cdef public object port
    cdef public bint multicast
    cdef public object question_type
    cdef public cython.dict _pending_handlers
    cdef public object _service_state_changed
    cdef public QueryScheduler query_scheduler
    cdef public bint done
    cdef public bint _first_request
    cdef public object _next_send_timer
    cdef public object _query_sender_task

    cpdef _enqueue_callback(self, object state_change, object type_, object name)

    @cython.locals(record_update=RecordUpdate, record=DNSRecord, cache=DNSCache, service=DNSRecord, pointer=DNSPointer)
    cpdef async_update_records(self, object zc, double now, cython.list records)

    cpdef cython.list _names_matching_types(self, object types)

    cpdef _fire_service_state_changed_event(self, cython.tuple event)

    cpdef async_update_records_complete(self)

    cpdef async_send_ready_queries(self, bint first_request, double now_millis, set ready_types)
