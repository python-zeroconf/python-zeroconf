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

import threading
from typing import Dict, List, Optional


from .._exceptions import ServiceNameAlreadyRegistered
from .._services import ServiceInfo


class ServiceRegistry:
    """A registry to keep track of services.

    This class exists to ensure services can
    be safely added and removed with thread
    safety.
    """

    def __init__(
        self,
    ) -> None:
        """Create the ServiceRegistry class."""
        self._services = {}  # type: Dict[str, ServiceInfo]
        self.types = {}  # type: Dict[str, List]
        self.servers = {}  # type: Dict[str, List]
        self._lock = threading.Lock()  # add and remove services thread safe

    def add(self, info: ServiceInfo) -> None:
        """Add a new service to the registry."""

        with self._lock:
            self._add(info)

    def remove(self, info: ServiceInfo) -> None:
        """Remove a new service from the registry."""

        with self._lock:
            self._remove(info)

    def update(self, info: ServiceInfo) -> None:
        """Update new service in the registry."""

        with self._lock:
            self._remove(info)
            self._add(info)

    def get_service_infos(self) -> List[ServiceInfo]:
        """Return all ServiceInfo."""
        return list(self._services.values())

    def get_info_name(self, name: str) -> Optional[ServiceInfo]:
        """Return all ServiceInfo for the name."""
        return self._services.get(name.lower())

    def get_types(self) -> List[str]:
        """Return all types."""
        return list(self.types.keys())

    def get_infos_type(self, type_: str) -> List[ServiceInfo]:
        """Return all ServiceInfo matching type."""
        return self._get_by_index("types", type_)

    def get_infos_server(self, server: str) -> List[ServiceInfo]:
        """Return all ServiceInfo matching server."""
        return self._get_by_index("servers", server)

    def _get_by_index(self, attr: str, key: str) -> List[ServiceInfo]:
        """Return all ServiceInfo matching the index."""
        service_infos = []

        for name in getattr(self, attr).get(key.lower(), [])[:]:
            info = self._services.get(name)
            # Since we do not get under a lock since it would be
            # a performance issue, its possible
            # the service can be unregistered during the get
            # so we must check if info is None
            if info is not None:
                service_infos.append(info)

        return service_infos

    def _add(self, info: ServiceInfo) -> None:
        """Add a new service under the lock."""
        if info.key in self._services:
            raise ServiceNameAlreadyRegistered

        self._services[info.key] = info
        self.types.setdefault(info.type.lower(), []).append(info.key)
        self.servers.setdefault(info.server_key, []).append(info.key)

    def _remove(self, info: ServiceInfo) -> None:
        """Remove a service under the lock."""
        old_service_info = self._services[info.key]
        self.types[old_service_info.type.lower()].remove(info.key)
        self.servers[old_service_info.server_key].remove(info.key)
        del self._services[info.key]
