
import cython

from .._cache cimport DNSCache
from .._dns cimport DNSQuestion, DNSRecord
from .._protocol.incoming cimport DNSIncoming
from .._updates cimport RecordUpdateListener
from .._utils.time cimport current_time_millis


cdef cython.float _DNS_PTR_MIN_TTL
cdef cython.uint _TYPE_PTR
cdef object _ADDRESS_RECORD_TYPES
cdef object RecordUpdate
cdef bint TYPE_CHECKING
cdef object _TYPE_PTR


cdef class RecordManager:

    cdef public object zc
    cdef public DNSCache cache
    cdef public cython.set listeners

    cpdef async_updates(self, object now, object records)

    cpdef async_updates_complete(self, object notify)

    @cython.locals(
        cache=DNSCache,
        record=DNSRecord,
        answers=cython.list,
        maybe_entry=DNSRecord,
        now_double=double
    )
    cpdef async_updates_from_response(self, DNSIncoming msg)

    cpdef async_add_listener(self, RecordUpdateListener listener, object question)

    cpdef async_remove_listener(self, RecordUpdateListener listener)

    @cython.locals(question=DNSQuestion, record=DNSRecord)
    cdef _async_update_matching_records(self, RecordUpdateListener listener, cython.list questions)
