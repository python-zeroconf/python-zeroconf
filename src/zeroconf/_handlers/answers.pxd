
import cython

from .._dns cimport DNSRecord
from .._protocol.outgoing cimport DNSOutgoing


cdef class QuestionAnswers:

    cdef public cython.dict ucast
    cdef public cython.dict mcast_now
    cdef public cython.dict mcast_aggregate
    cdef public cython.dict mcast_aggregate_last_second


cdef class AnswerGroup:

    cdef public object send_after
    cdef public object send_before
    cdef public cython.dict answers




cdef object _FLAGS_QR_RESPONSE_AA
cdef object NAME_GETTER

cpdef construct_outgoing_multicast_answers(cython.dict answers)

cpdef construct_outgoing_unicast_answers(
    cython.dict answers, bint ucast_source, cython.list questions, object id_
)

@cython.locals(answer=DNSRecord, additionals=cython.set, additional=DNSRecord)
cdef _add_answers_additionals(DNSOutgoing out, cython.dict answers)
