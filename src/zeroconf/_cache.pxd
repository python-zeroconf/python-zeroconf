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
cdef object _UNIQUE_RECORD_TYPES

cdef _remove_key(cython.dict cache, object key, DNSRecord record)


cdef class DNSCache:

    cdef public cython.dict cache
    cdef public cython.dict service_cache

    cdef _async_add(self, DNSRecord record)

    cdef _async_remove(self, DNSRecord record)

    @cython.locals(
        store=cython.dict
    )
    cpdef async_get_unique(self, DNSRecord record)

    cpdef async_all_by_details(self, str name, object type_, object class_)

    cpdef async_entries_with_name(self, str name)

    cpdef async_entries_with_server(self, str name)

    cpdef get_by_details(self, str name, object type_, object class_)

    cpdef get_all_by_details(self, str name, object type_, object class_)


cdef _dns_record_matches(DNSRecord record, object key, object type_, object class_)
