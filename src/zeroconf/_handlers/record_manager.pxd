
import cython

from .._cache cimport DNSCache
from .._dns cimport DNSRecord
from .._protocol.incoming cimport DNSIncoming


cdef cython.float _DNS_PTR_MIN_TTL
cdef object _ADDRESS_RECORD_TYPES
cdef object RecordUpdate

cdef class RecordManager:

    cdef object zc
    cdef DNSCache cache
    cdef cython.list listeners

    @cython.locals(
        cache=DNSCache,
        record=DNSRecord
    )
    cpdef async_updates_from_response(self, DNSIncoming msg)
