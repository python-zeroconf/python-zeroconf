
import cython


cdef object _LEN_BYTE
cdef object _LEN_SHORT
cdef object _LEN_INT

cdef object _NAME_COMPRESSION_MIN_SIZE
cdef object _BASE_MAX_SIZE

cdef object _EXPIRE_FULL_TIME_MS
cdef object _EXPIRE_STALE_TIME_MS
cdef object _RECENT_TIME_MS

cdef object _CLASS_UNIQUE
cdef object _CLASS_MASK

cdef object current_time_millis

cdef class DNSEntry:

    cdef public object key
    cdef public object name
    cdef public object type
    cdef public object class_
    cdef public object unique

    cdef _dns_entry_matches(self, DNSEntry other)

cdef class DNSQuestion(DNSEntry):

    cdef public cython.int _hash

cdef class DNSRecord(DNSEntry):

    cdef public object ttl
    cdef public object created

    cdef _suppressed_by_answer(self, DNSRecord answer)


cdef class DNSAddress(DNSRecord):

    cdef public cython.int _hash
    cdef public object address
    cdef public object scope_id

    cdef _eq(self, DNSAddress other)


cdef class DNSHinfo(DNSRecord):

    cdef public cython.int _hash
    cdef public object cpu
    cdef public object os

    cdef _eq(self, DNSHinfo other)


cdef class DNSPointer(DNSRecord):

    cdef public cython.int _hash
    cdef public object alias
    cdef public object alias_key

    cdef _eq(self, DNSPointer other)


cdef class DNSText(DNSRecord):

    cdef public cython.int _hash
    cdef public object text

    cdef _eq(self, DNSText other)


cdef class DNSService(DNSRecord):

    cdef public cython.int _hash
    cdef public object priority
    cdef public object weight
    cdef public object port
    cdef public object server
    cdef public object server_key

    cdef _eq(self, DNSService other)


cdef class DNSNsec(DNSRecord):

    cdef public cython.int _hash
    cdef public object next_name
    cdef public cython.list rdtypes

    cdef _eq(self, DNSNsec other)


cdef class DNSRRSet:

    cdef _record_sets
    cdef cython.dict _lookup

    @cython.locals(other=DNSRecord)
    cpdef suppresses(self, DNSRecord record)

    @cython.locals(lookup=cython.dict)
    cdef cython.dict _get_lookup(self)
