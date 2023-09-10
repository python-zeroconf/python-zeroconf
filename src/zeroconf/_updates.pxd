
import cython


cdef class RecordUpdateListener:

    cpdef async_update_records(self, object zc, object now, cython.list records)

    cpdef async_update_records_complete(self)
