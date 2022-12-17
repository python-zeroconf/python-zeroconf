
import cython


cdef class DNSIncoming:

    cdef public object _seen_logs
    cdef public object offset
    cdef public object data
    cdef public object data_len
    cdef public object name_cache
    cdef public object questions
    cdef object _answers
    cdef object id
    cdef object num_questions
    cdef object num_answers
    cdef object num_authorities
    cdef object num_additionals
    cdef object valid
    cdef object now
    cdef object scope_id
    cdef object source
