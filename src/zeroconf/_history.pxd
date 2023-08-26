import cython


cdef cython.double _DUPLICATE_QUESTION_INTERVAL

cdef class QuestionHistory:

    cdef cython.dict _history


    @cython.locals(than=cython.double, previous_question=cython.tuple, previous_known_answers=cython.set)
    cpdef suppresses(self, object question, cython.double now, cython.set known_answers)


    @cython.locals(than=cython.double, now_known_answers=cython.tuple)
    cpdef async_expire(self, cython.double now)
