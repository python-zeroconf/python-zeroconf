
import cython

from .._cache cimport DNSCache
from .._dns cimport DNSRecord
from .._protocol.incoming cimport DNSIncoming


cdef cython.float _DNS_PTR_MIN_TTL
cdef object _ADDRESS_RECORD_TYPES
cdef object RecordUpdate
cdef object TYPE_CHECKING
cdef object _TYPE_PTR

cdef class RecordManager:

    cdef public object zc
    cdef public DNSCache cache
    cdef public cython.list listeners

    cpdef async_updates(self, object now, object records)

    cpdef async_updates_complete(self, object notify)

    @cython.locals(
        cache=DNSCache,
        record=DNSRecord,
        maybe_entry=DNSRecord,
        now_float=cython.float
    )
    cpdef async_updates_from_response(self, DNSIncoming msg)
