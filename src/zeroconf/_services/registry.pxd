
import cython


cdef class ServiceRegistry:

    cdef cython.dict _services
    cdef public cython.dict types
    cdef public cython.dict servers

    @cython.locals(
        record_list=cython.list,
    )
    cdef _async_get_by_index(self, cython.dict records, str key)

    cdef _add(self, object info)

    cdef _remove(self, cython.list infos)
