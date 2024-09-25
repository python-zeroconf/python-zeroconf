
import cython

cdef class _WrappedTransport:

    cdef public object transport
    cdef public bint is_ipv6
    cdef public object sock
    cdef public int fileno
    cdef public tuple sock_name
