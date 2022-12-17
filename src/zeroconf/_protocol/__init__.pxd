

from zeroconf._logger cimport QuietLogger


cdef class DNSMessage:

   cdef public object flags
