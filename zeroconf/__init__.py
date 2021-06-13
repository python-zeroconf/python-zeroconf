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

from .cache import DNSCache  # noqa # import needed for backwards compat
from ._core import NotifyListener, Zeroconf  # noqa # import needed for backwards compat
from ._dns import (  # noqa # import needed for backwards compat
    DNSAddress,
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
from ._logger import QuietLogger, log  # noqa # import needed for backwards compat
from ._exceptions import (  # noqa # import needed for backwards compat
    AbstractMethodException,
    BadTypeInNameException,
    Error,
    IncomingDecodeError,
    NamePartTooLongException,
    NonUniqueNameException,
    ServiceNameAlreadyRegistered,
)
from .services import (  # noqa # import needed for backwards compat
    instance_name_from_service_info,
    Signal,
    SignalRegistrationInterface,
    RecordUpdateListener,
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
