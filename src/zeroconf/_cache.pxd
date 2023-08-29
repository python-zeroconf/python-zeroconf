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


cdef object _UNIQUE_RECORD_TYPES
cdef object _TYPE_PTR
cdef object _ONE_SECOND

cdef _remove_key(cython.dict cache, object key, DNSRecord record)


cdef class DNSCache:

    cdef public cython.dict cache
    cdef public cython.dict service_cache

    cpdef async_add_records(self, object entries)

    cpdef async_remove_records(self, object entries)

    cpdef async_get_unique(self, DNSRecord entry)

    @cython.locals(
        records=cython.dict,
        record=DNSRecord,
    )
    cdef _async_all_by_details(self, object name, object type_, object class_)

    cdef _async_add(self, DNSRecord record)

    cdef _async_remove(self, DNSRecord record)

    cpdef async_mark_unique_records_older_than_1s_to_expire(self, object unique_types, object answers, object now)

    @cython.locals(
        record=DNSRecord,
    )
    cdef _async_mark_unique_records_older_than_1s_to_expire(self, object unique_types, object answers, object now)

cdef _dns_record_matches(DNSRecord record, object key, object type_, object class_)
