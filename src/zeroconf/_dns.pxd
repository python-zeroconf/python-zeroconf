


cdef object _LEN_BYTE
cdef object _LEN_SHORT
cdef object _LEN_INT

cdef object _NAME_COMPRESSION_MIN_SIZE
cdef object _BASE_MAX_SIZE

cdef object _EXPIRE_FULL_TIME_MS
cdef object _EXPIRE_STALE_TIME_MS
cdef object _RECENT_TIME_MS


cdef class DNSEntry:

    cdef public key
    cdef public name
    cdef public type
    cdef public class_
    cdef public unique

cdef class DNSQuestion(DNSEntry):

    cdef public _hash

cdef class DNSRecord(DNSEntry):

    cdef public ttl
    cdef public created

cdef class DNSAddress(DNSRecord):

    cdef public _hash
    cdef public address
    cdef public scope_id


cdef class DNSHinfo(DNSRecord):

    cdef public _hash
    cdef public cpu
    cdef public os


cdef class DNSPointer(DNSRecord):

    cdef public _hash
    cdef public alias

cdef class DNSText(DNSRecord):

    cdef public _hash
    cdef public text

cdef class DNSService(DNSRecord):

    cdef public _hash
    cdef public priority
    cdef public weight
    cdef public port
    cdef public server
    cdef public server_key

cdef class DNSNsec(DNSRecord):

    cdef public _hash
    cdef public next_name
    cdef public rdtypes


cdef class DNSRRSet:

    cdef _records
    cdef _lookup
