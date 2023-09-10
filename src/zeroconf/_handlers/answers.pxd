
import cython

from .._protocol.outgoing cimport DNSOutgoing


cdef object _FLAGS_QR_RESPONSE_AA
cdef object NAME_GETTER

cpdef construct_outgoing_multicast_answers(cython.dict answers)

cpdef construct_outgoing_unicast_answers(
    cython.dict answers, object ucast_source, cython.list questions, object id_
)

cdef _add_answers_additionals(DNSOutgoing out, cython.dict answers)
