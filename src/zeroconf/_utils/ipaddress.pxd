cdef bint TYPE_CHECKING
cdef bint IPADDRESS_SUPPORTS_SCOPE_ID

cdef get_ip_address_object_from_record(DNSAddress record)

@cython.locals(address_str=str)
cdef str_without_scope_id(object addr)

cdef ip_bytes_and_scope_to_address(object addr, object scope_id)

cdef object cached_ip_addresses_wrapper
