"""A pure python implementation of multicast DNS service discovery.

Licensed under LGPL-2.1-or-later; see COPYING for details. This file is
part of a continuously modified work; modification dates are recorded
in the project's git history.
"""

from __future__ import annotations


class Error(Exception):
    """Base class for all zeroconf exceptions."""


class AbstractMethodException(Error):
    """Exception when a required method is not implemented."""


class BadTypeInNameException(Error):
    """Exception when the type in a name is invalid."""


class EventLoopBlocked(Error):
    """Exception when the event loop is blocked.

    This exception is never expected to be thrown
    during normal operation. It should only happen
    when the cpu is maxed out or there is something blocking
    the event loop.
    """


class IncomingDecodeError(Error):
    """Exception when there is invalid data in an incoming packet."""


class NamePartTooLongException(Error):
    """Exception when the name is too long."""


class NonUniqueNameException(Error):
    """Exception when the name is already registered."""


class NotRunningException(Error):
    """Exception when an action is called with a zeroconf instance that is not running.

    The instance may not be running because it was already shutdown
    or startup has failed in some unexpected way.
    """


class ServiceNameAlreadyRegistered(Error):
    """Exception when a service name is already registered."""
