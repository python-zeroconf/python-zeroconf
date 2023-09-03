
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

    cpdef async_get_info_name(self, str name)

    cpdef async_get_types(self)

    cpdef async_get_infos_type(self, str type_)

    cpdef async_get_infos_server(self, str server)
