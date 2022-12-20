
import cython

from .incoming cimport DNSIncoming


cdef cython.uint _CLASS_UNIQUE
cdef cython.uint _DNS_PACKET_HEADER_LEN
cdef cython.uint _FLAGS_QR_MASK
cdef cython.uint _FLAGS_QR_QUERY
cdef cython.uint _FLAGS_QR_RESPONSE
cdef cython.uint _FLAGS_TC
cdef cython.uint _MAX_MSG_ABSOLUTE
cdef cython.uint _MAX_MSG_TYPICAL


cdef class DNSOutgoing:

    cdef public unsigned int flags
    cdef public object finished
    cdef public object id
    cdef public bint multicast
    cdef public cython.list packets_data
    cdef public object names
    cdef public cython.list data
    cdef public unsigned int size
    cdef public object allow_long
    cdef public object state
    cdef public cython.list questions
    cdef public cython.list answers
    cdef public cython.list authorities
    cdef public cython.list additionals

    cdef _reset_for_next_packet(self)

    cdef _write_byte(self, object value)

    cdef _insert_short_at_start(self, object value)

    cdef _replace_short(self, object index, object value)

    cdef _write_int(self, object value)

    cdef _write_question(self, object question)

    cdef _write_record_class(self, object record)

    cdef _check_data_limit_or_rollback(self, object start_data_length, object start_size)

    cdef _write_questions_from_offset(self, object questions_offset)

    cdef _write_answers_from_offset(self, object answer_offset)

    cdef _write_records_from_offset(self, object records, object offset)

    cdef _has_more_to_add(self, object questions_offset, object answer_offset, object authority_offset, object additional_offset)

    @cython.locals(
        questions_offset=cython.uint,
        answer_offset=cython.uint,
        authority_offset=cython.uint,
        additional_offset=cython.uint,
        questions_written=cython.uint,
        answers_written=cython.uint,
        authorities_written=cython.uint,
        additionals_written=cython.uint,
    )
    cdef _packets(self)
