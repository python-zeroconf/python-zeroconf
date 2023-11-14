
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
cdef object SERVICE_STATE_CHANGE_ADDED, SERVICE_STATE_CHANGE_REMOVED, SERVICE_STATE_CHANGE_UPDATED
cdef cython.set _ADDRESS_RECORD_TYPES

cdef class _DNSPointerOutgoingBucket:

    cdef public object now
    cdef public DNSOutgoing out
    cdef public cython.uint bytes

    cpdef add(self, cython.uint max_compressed_size, DNSQuestion question, cython.set answers)

@cython.locals(cache=DNSCache, question_history=QuestionHistory, record=DNSRecord, qu_question=bint)
cpdef generate_service_query(
    object zc,
    float now,
    list type_,
    bint multicast,
    object question_type
)

@cython.locals(answer=DNSPointer, query_buckets=list, question=DNSQuestion, max_compressed_size=cython.uint, max_bucket_size=cython.uint, query_bucket=_DNSPointerOutgoingBucket)
cdef _group_ptr_queries_with_known_answers(object now, object multicast, cython.dict question_with_known_answers)

cdef class QueryScheduler:

    cdef cython.set _types
    cdef cython.dict _next_time
    cdef object _first_random_delay_interval
    cdef cython.dict _delay

    cpdef millis_to_wait(self, object now)

    cpdef reschedule_type(self, object type_, object next_time)

    cpdef process_ready_types(self, object now)

cdef class _ServiceBrowserBase(RecordUpdateListener):

    cdef public cython.set types
    cdef public object zc
    cdef DNSCache _cache
    cdef object _loop
    cdef public object addr
    cdef public object port
    cdef public object multicast
    cdef public object question_type
    cdef public cython.dict _pending_handlers
    cdef public object _service_state_changed
    cdef public QueryScheduler query_scheduler
    cdef public bint done
    cdef public object _first_request
    cdef public object _next_send_timer
    cdef public object _query_sender_task

    cpdef _generate_ready_queries(self, object first_request, object now)

    cpdef _enqueue_callback(self, object state_change, object type_, object name)

    @cython.locals(record_update=RecordUpdate, record=DNSRecord, cache=DNSCache, service=DNSRecord, pointer=DNSPointer)
    cpdef async_update_records(self, object zc, cython.float now, cython.list records)

    cpdef cython.list _names_matching_types(self, object types)

    cpdef reschedule_type(self, object type_, object now, object next_time)

    cpdef _fire_service_state_changed_event(self, cython.tuple event)

    cpdef _async_send_ready_queries_schedule_next(self)

    cpdef _async_schedule_next(self, object now)

    cpdef _async_send_ready_queries(self, object now)

    cpdef _cancel_send_timer(self)

    cpdef async_update_records_complete(self)
