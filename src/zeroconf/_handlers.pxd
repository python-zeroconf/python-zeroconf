
import cython

from ._cache cimport DNSCache
from ._dns cimport DNSAddress, DNSNsec, DNSPointer, DNSQuestion, DNSRecord, DNSRRSet
from ._protocol.incoming cimport DNSIncoming
from ._protocol.outgoing cimport DNSOutgoing


cdef object RecordUpdate
cdef object _DNS_PTR_MIN_TTL

cdef class QueryHandler:

    cdef object registry
    cdef DNSCache cache
    cdef object question_history

cdef class RecordManager:

    cdef object zc
    cdef DNSCache cache
    cdef public cython.list listeners

cdef class _QueryResponse:

    cdef bint _is_probe
    cdef DNSIncoming _msg
    cdef object _now
    cdef DNSCache _cache
    cdef object _additionals
    cdef cython.set _ucast
    cdef cython.set _mcast_now
    cdef cython.set _mcast_aggregate
    cdef cython.set _mcast_aggregate_last_second
