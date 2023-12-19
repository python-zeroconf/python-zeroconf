
import cython


cdef class _WrappedTransport:

    cdef public object transport
    cdef public bint is_ipv6
    cdef public object socket
    cdef public object fileno
    cdef public tuple sock_name
