
import cython

from .._cache cimport DNSCache
from .._dns cimport DNSPointer, DNSQuestion, DNSRecord, DNSRRSet
from .._history cimport QuestionHistory
from .._protocol.incoming cimport DNSIncoming
from .._services.registry cimport ServiceRegistry


cdef object TYPE_CHECKING, QuestionAnswers
cdef cython.uint _ONE_SECOND, _TYPE_PTR, _TYPE_ANY, _TYPE_A, _TYPE_AAAA, _TYPE_SRV, _TYPE_TXT
cdef str _SERVICE_TYPE_ENUMERATION_NAME
cdef cython.set _RESPOND_IMMEDIATE_TYPES

cdef class _QueryResponse:

    cdef object _is_probe
    cdef DNSIncoming _msg
    cdef float _now
    cdef DNSCache _cache
    cdef cython.dict _additionals
    cdef cython.set _ucast
    cdef cython.set _mcast_now
    cdef cython.set _mcast_aggregate
    cdef cython.set _mcast_aggregate_last_second

    cpdef add_qu_question_response(self, cython.dict answers)

    cpdef add_ucast_question_response(self, cython.dict answers)

    cpdef add_mcast_question_response(self, cython.dict answers)

    @cython.locals(maybe_entry=DNSRecord)
    cpdef _has_mcast_within_one_quarter_ttl(self, DNSRecord record)

    @cython.locals(maybe_entry=DNSRecord)
    cpdef _has_mcast_record_in_last_second(self, DNSRecord record)

    cpdef answers(self)

cdef class QueryHandler:

    cdef ServiceRegistry registry
    cdef DNSCache cache
    cdef QuestionHistory question_history

    cdef _add_service_type_enumeration_query_answers(self, cython.dict answer_set, DNSRRSet known_answers)

    cdef _add_pointer_answers(self, str lower_name, cython.dict answer_set, DNSRRSet known_answers)

    cdef _add_address_answers(self, str lower_name, cython.dict answer_set, DNSRRSet known_answers, cython.uint type_)

    @cython.locals(question_lower_name=str, type_=cython.uint)
    cdef _answer_question(self, DNSQuestion question, DNSRRSet known_answers)

    @cython.locals(
        msg=DNSIncoming,
        question=DNSQuestion,
        answer_set=cython.dict,
        known_answers=DNSRRSet,
        known_answers_set=cython.set,
    )
    cpdef async_response(self, cython.list msgs, object unicast_source)
