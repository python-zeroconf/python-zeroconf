""" Multicast DNS Service Discovery for Python, v0.14-wmcbrine
    Copyright 2003 Paul Scott-Murphy, 2014 William McBrine

    This module provides a framework for the use of DNS Service Discovery
    using IP multicast.

    This library is free software; you can redistribute it and/or
    modify it under the terms of the GNU Lesser General Public
    License as published by the Free Software Foundation; either
    version 2.1 of the License, or (at your option) any later version.

    This library is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
    Lesser General Public License for more details.

    You should have received a copy of the GNU Lesser General Public
    License along with this library; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA 02110-1301
    USA
"""

import sys

from .const import (  # noqa # import needed for backwards compat
    _BROWSER_BACKOFF_LIMIT,
    _BROWSER_TIME,
    _CACHE_CLEANUP_INTERVAL,
    _CHECK_TIME,
    _CLASSES,
    _CLASS_IN,
    _CLASS_NONE,
    _CLASS_MASK,
    _CLASS_UNIQUE,
    _DNS_HOST_TTL,
    _DNS_OTHER_TTL,
    _DNS_PORT,
    _EXPIRE_FULL_TIME_PERCENT,
    _EXPIRE_REFRESH_TIME_PERCENT,
    _EXPIRE_STALE_TIME_PERCENT,
    _FLAGS_AA,
    _FLAGS_QR_MASK,
    _FLAGS_QR_QUERY,
    _FLAGS_QR_RESPONSE,
    _FLAGS_TC,
    _HAS_ASCII_CONTROL_CHARS,
    _HAS_A_TO_Z,
    _HAS_ONLY_A_TO_Z_NUM_HYPHEN,
    _HAS_ONLY_A_TO_Z_NUM_HYPHEN_UNDERSCORE,
    _IPPROTO_IPV6,
    _LISTENER_TIME,
    _LOCAL_TRAILER,
    _MAX_MSG_ABSOLUTE,
    _MAX_MSG_TYPICAL,
    _MDNS_ADDR,
    _MDNS_ADDR6,
    _MDNS_ADDR6_BYTES,
    _MDNS_ADDR_BYTES,
    _MDNS_PORT,
    _NONTCP_PROTOCOL_LOCAL_TRAILER,
    _REGISTER_TIME,
    _SERVICE_TYPE_ENUMERATION_NAME,
    _TCP_PROTOCOL_LOCAL_TRAILER,
    _TYPES,
    _TYPE_A,
    _TYPE_AAAA,
    _TYPE_ANY,
    _TYPE_CNAME,
    _TYPE_HINFO,
    _TYPE_PTR,
    _TYPE_SOA,
    _TYPE_SRV,
    _TYPE_TXT,
    _UNREGISTER_TIME,
)
from .core import NotifyListener, Zeroconf  # noqa # import needed for backwards compat
from .dns import (  # noqa # import needed for backwards compat
    DNSAddress,
    DNSCache,
    DNSEntry,
    DNSHinfo,
    DNSIncoming,
    DNSOutgoing,
    DNSPointer,
    DNSQuestion,
    DNSRecord,
    DNSService,
    DNSText,
)
from .exceptions import (  # noqa # import needed for backwards compat
    AbstractMethodException,
    BadTypeInNameException,
    Error,
    IncomingDecodeError,
    NamePartTooLongException,
    NonUniqueNameException,
    ServiceNameAlreadyRegistered,
)
from .logger import QuietLogger, log  # noqa # import needed for backwards compat
from .services import (  # noqa # import needed for backwards compat
    instance_name_from_service_info,
    Signal,
    SignalRegistrationInterface,
    RecordUpdateListener,
    _ServiceBrowserBase,
    ServiceBrowser,
    ServiceInfo,
    ServiceListener,
    ServiceStateChange,
)
from .services.registry import ServiceRegistry  # noqa # import needed for backwards compat
from .services.types import ZeroconfServiceTypes  # noqa # import needed for backwards compat
from .utils.name import service_type_name  # noqa # import needed for backwards compat
from .utils.net import (  # noqa # import needed for backwards compat
    add_multicast_member,
    can_send_to,
    autodetect_ip_version,
    create_sockets,
    get_all_addresses_v6,
    InterfaceChoice,
    InterfacesType,
    IPVersion,
    _is_v6_address,
    _encode_address,
    get_all_addresses,
)
from .utils.struct import int2byte  # noqa # import needed for backwards compat
from .utils.time import current_time_millis, millis_to_seconds  # noqa # import needed for backwards compat

__author__ = 'Paul Scott-Murphy, William McBrine'
__maintainer__ = 'Jakub Stasiak <jakub@stasiak.at>'
__version__ = '0.31.0'
__license__ = 'LGPL'


__all__ = [
    "__version__",
    "Zeroconf",
    "ServiceInfo",
    "ServiceBrowser",
    "ServiceListener",
    "Error",
    "InterfaceChoice",
    "ServiceStateChange",
    "IPVersion",
]

if sys.version_info <= (3, 6):
    raise ImportError(
        '''
Python version > 3.6 required for python-zeroconf.
If you need support for Python 2 or Python 3.3-3.4 please use version 19.1
If you need support for Python 3.5 please use version 0.28.0
    '''
    )
