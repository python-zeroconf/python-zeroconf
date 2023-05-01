
import cython


cdef cython.uint DNS_COMPRESSION_HEADER_LEN
cdef cython.uint MAX_DNS_LABELS
cdef cython.uint DNS_COMPRESSION_POINTER_LEN
cdef cython.uint MAX_NAME_LENGTH

cdef object current_time_millis

cdef cython.uint _TYPE_A
cdef cython.uint _TYPE_CNAME
cdef cython.uint _TYPE_PTR
cdef cython.uint _TYPE_TXT
cdef cython.uint _TYPE_SRV
cdef cython.uint _TYPE_HINFO
cdef cython.uint _TYPE_AAAA
cdef cython.uint _TYPE_NSEC
cdef cython.uint _FLAGS_QR_MASK
cdef cython.uint _FLAGS_QR_MASK
cdef cython.uint _FLAGS_TC
cdef cython.uint _FLAGS_QR_QUERY
cdef cython.uint _FLAGS_QR_RESPONSE

cdef object UNPACK_3H
cdef object UNPACK_6H
cdef object UNPACK_HH
cdef object UNPACK_HHiH

cdef object DECODE_EXCEPTIONS

cdef object IncomingDecodeError

from .._dns cimport (
    DNSAddress,
    DNSEntry,
    DNSHinfo,
    DNSNsec,
    DNSPointer,
    DNSQuestion,
    DNSRecord,
    DNSService,
    DNSText,
)


cdef class DNSIncoming:

    cdef bint _did_read_others
    cdef public unsigned int flags
    cdef object offset
    cdef public bytes data
    cdef unsigned int _data_len
    cdef public cython.dict name_cache
    cdef public cython.list questions
    cdef object _answers
    cdef public object id
    cdef public cython.uint num_questions
    cdef public cython.uint num_answers
    cdef public cython.uint num_authorities
    cdef public cython.uint num_additionals
    cdef public object valid
    cdef public object now
    cdef public object scope_id
    cdef public object source

    @cython.locals(
        off=cython.uint,
        label_idx=cython.uint,
        length=cython.uint,
        link=cython.uint,
        link_data=cython.uint
    )
    cdef _decode_labels_at_offset(self, unsigned int off, cython.list labels, cython.set seen_pointers)

    cdef _read_header(self)

    cdef _initial_parse(self)

    cdef _unpack(self, object unpacker, object length)

    @cython.locals(
        end=cython.uint,
        length=cython.uint
    )
    cdef _read_others(self)

    cdef _read_questions(self)

    @cython.locals(
        length=cython.uint
    )
    cdef bytes _read_character_string(self)

    cdef _read_string(self, unsigned int length)

    @cython.locals(
        name_start=cython.uint
    )
    cdef _read_record(self, object domain, unsigned int type_, object class_, object ttl, unsigned int length)

    cdef _read_bitmap(self, unsigned int end)

    cdef _read_name(self)
