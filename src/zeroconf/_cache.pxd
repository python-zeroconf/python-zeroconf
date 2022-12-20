
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

cdef class DNSCache:

    cdef public object _cache
    cdef public object service_cache


cdef _dns_entry_matches(DNSEntry entry, object key, object type_, object class_)
