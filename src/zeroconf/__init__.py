"""A pure python implementation of multicast DNS service discovery.

Licensed under LGPL-2.1-or-later; see COPYING for details. This file is
part of a continuously modified work; modification dates are recorded
in the project's git history.
"""

from __future__ import annotations

from ._cache import DNSCache  # noqa # import needed for backwards compat
from ._core import Zeroconf
from ._dns import (  # noqa # import needed for backwards compat
    DNSAddress,
    DNSEntry,
    DNSHinfo,
    DNSNsec,
    DNSPointer,
    DNSQuestion,
    DNSQuestionType,
    DNSRecord,
    DNSService,
    DNSText,
)
from ._exceptions import (
    AbstractMethodException,
    BadTypeInNameException,
    Error,
    EventLoopBlocked,
    IncomingDecodeError,
    NamePartTooLongException,
    NonUniqueNameException,
    NotRunningException,
    ServiceNameAlreadyRegistered,
)
from ._logger import QuietLogger, log  # noqa # import needed for backwards compat
from ._protocol.incoming import DNSIncoming  # noqa # import needed for backwards compat
from ._protocol.outgoing import DNSOutgoing  # noqa # import needed for backwards compat
from ._record_update import RecordUpdate
from ._services import (  # noqa # import needed for backwards compat
    ServiceListener,
    ServiceStateChange,
    Signal,
    SignalRegistrationInterface,
)
from ._services.browser import ServiceBrowser
from ._services.info import (  # noqa # import needed for backwards compat
    AddressResolver,
    AddressResolverIPv4,
    AddressResolverIPv6,
    ServiceInfo,
    instance_name_from_service_info,
)
from ._services.registry import (  # noqa # import needed for backwards compat
    ServiceRegistry,
)
from ._services.types import ZeroconfServiceTypes
from ._updates import RecordUpdateListener
from ._utils.name import service_type_name  # noqa # import needed for backwards compat
from ._utils.net import (  # noqa # import needed for backwards compat
    InterfaceChoice,
    InterfacesType,
    IPVersion,
    add_multicast_member,
    autodetect_ip_version,
    create_sockets,
    get_all_addresses,
    get_all_addresses_v6,
)
from ._utils.time import (  # noqa # import needed for backwards compat
    current_time_millis,
    millis_to_seconds,
)

__author__ = "The python-zeroconf authors"  # full history in COPYING and git
__maintainer__ = "J. Nick Koston <nick@koston.org>"
__version__ = "0.151.3"
__license__ = "LGPL"


__all__ = [
    "AbstractMethodException",
    "BadTypeInNameException",
    "DNSQuestionType",
    # Exceptions
    "Error",
    "EventLoopBlocked",
    "IPVersion",
    "IncomingDecodeError",
    "InterfaceChoice",
    "NamePartTooLongException",
    "NonUniqueNameException",
    "NotRunningException",
    "RecordUpdate",
    "RecordUpdateListener",
    "ServiceBrowser",
    "ServiceInfo",
    "ServiceListener",
    "ServiceNameAlreadyRegistered",
    "ServiceStateChange",
    "Zeroconf",
    "ZeroconfServiceTypes",
    "__version__",
    "current_time_millis",
]
