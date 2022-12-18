
import cython


cdef cython.uint DNS_COMPRESSION_HEADER_LEN
cdef cython.uint MAX_DNS_LABELS
cdef cython.uint DNS_COMPRESSION_POINTER_LEN
cdef cython.uint MAX_NAME_LENGTH


cdef object _TYPE_A
cdef object _TYPE_CNAME
cdef object _TYPE_PTR
cdef object _TYPE_TXT
cdef object _TYPE_SRV
cdef object _TYPE_HINFO
cdef object _TYPE_AAAA
cdef object _TYPE_NSEC
cdef object _FLAGS_QR_MASK
cdef object _FLAGS_QR_MASK
cdef object _FLAGS_TC
cdef object _FLAGS_QR_QUERY
cdef object _FLAGS_QR_RESPONSE

cdef object UNPACK_3H
cdef object UNPACK_6H
cdef object UNPACK_HH
cdef object UNPACK_HHiH

cdef object DECODE_EXCEPTIONS

cdef object IncomingDecodeError

cdef class DNSIncoming:

    cdef bint _did_read_others
    cdef public object flags
    cdef unsigned int offset
    cdef public bytes data
    cdef unsigned int _data_len
    cdef public object name_cache
    cdef public object questions
    cdef object _answers
    cdef public object id
    cdef public object num_questions
    cdef public object num_answers
    cdef public object num_authorities
    cdef public object num_additionals
    cdef public object valid
    cdef public object now
    cdef public object scope_id
    cdef public object source

    @cython.locals(
        off=cython.uint,
        label_idx=cython.uint,
        length=cython.uint,
        link=cython.uint
    )
    cdef _decode_labels_at_offset(self, unsigned int off, cython.list labels, object seen_pointers)

    cdef _read_header(self)

    cdef _read_questions(self)

    cdef _read_others(self)

    cdef _read_character_string(self)

    cdef _read_string(self, unsigned int length)

    cdef _parse_data(self, object parser_call)

    cdef _read_record(self, object domain, unsigned int type_, unsigned int class_, unsigned int ttl, unsigned int length)

    cdef _read_bitmap(self, unsigned int end)

    cdef _read_name(self)
