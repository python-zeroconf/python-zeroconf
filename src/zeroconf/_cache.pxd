import cython
from ._dns cimport (
    DNSAddress,
    DNSEntry,
    DNSHinfo,
    DNSPointer,
    DNSRecord,
    DNSService,
    DNSText,
)


cdef object _TYPE_PTR

cdef _remove_key(cython.dict cache, object key, DNSRecord record)


cdef class DNSCache:

    cdef public cython.dict cache
    cdef public cython.dict service_cache

    cdef _async_add(self, DNSRecord record)

    cdef _async_remove(self, DNSRecord record)


cdef _dns_record_matches(DNSRecord record, object key, object type_, object class_)
