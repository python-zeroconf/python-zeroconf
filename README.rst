python-zeroconf
===============

.. image:: https://github.com/jstasiak/python-zeroconf/workflows/CI/badge.svg
   :target: https://github.com/jstasiak/python-zeroconf?query=workflow%3ACI+branch%3Amaster

.. image:: https://img.shields.io/pypi/v/zeroconf.svg
    :target: https://pypi.python.org/pypi/zeroconf

.. image:: https://codecov.io/gh/jstasiak/python-zeroconf/branch/master/graph/badge.svg
   :target: https://codecov.io/gh/jstasiak/python-zeroconf

`Documentation <https://python-zeroconf.readthedocs.io/en/latest/>`_.
    
This is fork of pyzeroconf, Multicast DNS Service Discovery for Python,
originally by Paul Scott-Murphy (https://github.com/paulsm/pyzeroconf),
modified by William McBrine (https://github.com/wmcbrine/pyzeroconf).

The original William McBrine's fork note::

    This fork is used in all of my TiVo-related projects: HME for Python
    (and therefore HME/VLC), Network Remote, Remote Proxy, and pyTivo.
    Before this, I was tracking the changes for zeroconf.py in three
    separate repos. I figured I should have an authoritative source.
    
    Although I make changes based on my experience with TiVos, I expect that
    they're generally applicable. This version also includes patches found
    on the now-defunct (?) Launchpad repo of pyzeroconf, and elsewhere
    around the net -- not always well-documented, sorry.

Compatible with:

* Bonjour
* Avahi

Compared to some other Zeroconf/Bonjour/Avahi Python packages, python-zeroconf:

* isn't tied to Bonjour or Avahi
* doesn't use D-Bus
* doesn't force you to use particular event loop or Twisted
* is pip-installable
* has PyPI distribution

Python compatibility
--------------------

* CPython 3.6+
* PyPy3 5.8+

Versioning
----------

This project's versions follow the following pattern: MAJOR.MINOR.PATCH.

* MAJOR version has been 0 so far
* MINOR version is incremented on backward incompatible changes
* PATCH version is incremented on backward compatible changes

Status
------

There are some people using this package. I don't actively use it and as such
any help I can offer with regard to any issues is very limited.

IPv6 support
------------

IPv6 support is relatively new and currently limited, specifically:

* `InterfaceChoice.All` is an alias for `InterfaceChoice.Default` on non-POSIX
  systems.
* On Windows specific interfaces can only be requested as interface indexes,
  not as IP addresses.
* Dual-stack IPv6 sockets are used, which may not be supported everywhere (some
  BSD variants do not have them).
* Listening on localhost (`::1`) does not work. Help with understanding why is
  appreciated.

How to get python-zeroconf?
===========================

* PyPI page https://pypi.python.org/pypi/zeroconf
* GitHub project https://github.com/jstasiak/python-zeroconf

The easiest way to install python-zeroconf is using pip::

    pip install zeroconf



How do I use it?
================

Here's an example of browsing for a service:

.. code-block:: python

    from zeroconf import ServiceBrowser, Zeroconf
    
    
    class MyListener:
    
        def remove_service(self, zeroconf, type, name):
            print("Service %s removed" % (name,))
    
        def add_service(self, zeroconf, type, name):
            info = zeroconf.get_service_info(type, name)
            print("Service %s added, service info: %s" % (name, info))
    
    
    zeroconf = Zeroconf()
    listener = MyListener()
    browser = ServiceBrowser(zeroconf, "_http._tcp.local.", listener)
    try:
        input("Press enter to exit...\n\n")
    finally:
        zeroconf.close()

.. note::

    Discovery and service registration use *all* available network interfaces by default.
    If you want to customize that you need to specify ``interfaces`` argument when
    constructing ``Zeroconf`` object (see the code for details).

If you don't know the name of the service you need to browse for, try:

.. code-block:: python

    from zeroconf import ZeroconfServiceTypes
    print('\n'.join(ZeroconfServiceTypes.find()))

See examples directory for more.

Changelog
=========

0.29.0 (not released yet)
=========================

Backwards incompatible:

* Dropped Python 3.5 support

0.28.8
======

* Fixed the packet generation when multiple packets are necessary, previously invalid
  packets were generated sometimes. Patch thanks to J. Nick Koston.

0.28.7
======

* Fixed the IPv6 address rendering in the browser example, thanks to Alexey Vazhnov.
* Fixed a crash happening when a service is added or removed during handle_response
  and improved exception handling, thanks to J. Nick Koston.

0.28.6
======

* Loosened service name validation when receiving from the network this lets us handle
  some real world devices previously causing errors, thanks to J. Nick Koston.

0.28.5
======

* Enabled ignoring duplicated messages which decreases CPU usage, thanks to J. Nick Koston.
* Fixed spurious AttributeError: module 'unittest' has no attribute 'mock' in tests.

0.28.4
======

* Improved cache reaper performance significantly, thanks to J. Nick Koston.
* Added ServiceListener to __all__ as it's part of the public API, thanks to Justin Nesselrotte.

0.28.3
======

* Reduced a time an internal lock is held which should eliminate deadlocks in high-traffic networks,
  thanks to J. Nick Koston.

0.28.2
======

* Stopped asking questions we already have answers for in cache, thanks to Paul Daumlechner.
* Removed initial delay before querying for service info, thanks to Erik Montnemery.

0.28.1
======

* Fixed a resource leak connected to using ServiceBrowser with multiple types, thanks to
  J. Nick Koston.

0.28.0
======

* Improved Windows support when using socket errno checks, thanks to Sandy Patterson.
* Added support for passing text addresses to ServiceInfo.
* Improved logging (includes fixing an incorrect logging call)
* Improved Windows compatibility by using Adapter.index from ifaddr, thanks to PhilippSelenium.
* Improved Windows compatibility by stopping using socket.if_nameindex.
* Fixed an OS X edge case which should also eliminate a memory leak, thanks to Emil Styrke.

Technically backwards incompatible:

* ``ifaddr`` 0.1.7 or newer is required now.

0.27.1
------

* Improved the logging situation (includes fixing a false-positive "packets() made no progress
  adding records", thanks to Greg Badros)

0.27.0
------

* Large multi-resource responses are now split into separate packets which fixes a bad
  mdns-repeater/ChromeCast Audio interaction ending with ChromeCast Audio crash (and possibly
  some others) and improves RFC 6762 compliance, thanks to Greg Badros
* Added a warning presented when the listener passed to ServiceBrowser lacks update_service()
  callback
* Added support for finding all services available in the browser example, thanks to Perry Kunder

Backwards incompatible:

* Removed previously deprecated ServiceInfo address constructor parameter and property

0.26.3
------

* Improved readability of logged incoming data, thanks to Erik Montnemery
* Threads are given unique names now to aid debugging, thanks to Erik Montnemery
* Fixed a regression where get_service_info() called within a listener add_service method
  would deadlock, timeout and incorrectly return None, fix thanks to Erik Montnemery, but
  Matt Saxon and Hmmbob were also involved in debugging it.

0.26.2
------

* Added support for multiple types to ServiceBrowser, thanks to J. Nick Koston
* Fixed a race condition where a listener gets a message before the lock is created, thanks to
  J. Nick Koston

0.26.1
------

* Fixed a performance regression introduced in 0.26.0, thanks to J. Nick Koston (this is close in
  spirit to an optimization made in 0.24.5 by the same author)

0.26.0
------

* Fixed a regression where service update listener wasn't called on IP address change (it's called
  on SRV/A/AAAA record changes now), thanks to Matt Saxon

Technically backwards incompatible:

* Service update hook is no longer called on service addition (service added hook is still called),
  this is related to the fix above

0.25.1
------

* Eliminated 5s hangup when calling Zeroconf.close(), thanks to Erik Montnemery

0.25.0
------

* Reverted uniqueness assertions when browsing, they caused a regression

Backwards incompatible:

* Rationalized handling of TXT records. Non-bytes values are converted to str and encoded to bytes
  using UTF-8 now, None values mean value-less attributes. When receiving TXT records no decoding
  is performed now, keys are always bytes and values are either bytes or None in value-less
  attributes.

0.24.5
------

* Fixed issues with shared records being used where they shouldn't be (TXT, SRV, A records are
  unique now), thanks to Matt Saxon
* Stopped unnecessarily excluding host-only interfaces from InterfaceChoice.all as they don't
  forbid multicast, thanks to Andreas Oberritter
* Fixed repr() of IPv6 DNSAddress, thanks to Aldo Hoeben
* Removed duplicate update messages sent to listeners, thanks to Matt Saxon
* Added support for cooperating responders, thanks to Matt Saxon
* Optimized handle_response cache check, thanks to J. Nick Koston
* Fixed memory leak in DNSCache, thanks to J. Nick Koston

0.24.4
------

* Fixed resetting TTL in DNSRecord.reset_ttl(), thanks to Matt Saxon
* Improved various DNS class' string representations, thanks to Jay Hogg

0.24.3
------

* Fixed import-time "TypeError: 'ellipsis' object is not iterable." on CPython 3.5.2

0.24.2
------

* Added support for AWDL interface on macOS (needed and used by the opendrop project but should be
  useful in general), thanks to Milan Stute
* Added missing type hints

0.24.1
------

* Applied some significant performance optimizations, thanks to Jaime van Kessel for the patch and
  to Ghostkeeper for performance measurements
* Fixed flushing outdated cache entries when incoming record is unique, thanks to Michael Hu
* Fixed handling updates of TXT records (they'd not get recorded previously), thanks to Michael Hu

0.24.0
------

* Added IPv6 support, thanks to Dmitry Tantsur
* Added additional recommended records to PTR responses, thanks to Scott Mertz
* Added handling of ENOTCONN being raised during shutdown when using Eventlet, thanks to Tamás Nepusz
* Included the py.typed marker in the package so that type checkers know to use type hints from the
  source code, thanks to Dmitry Tantsur

0.23.0
------

* Added support for MyListener call getting updates to service TXT records, thanks to Matt Saxon
* Added support for multiple addresses when publishing a service, getting/setting single address
  has become deprecated. Change thanks to Dmitry Tantsur

Backwards incompatible:

* Dropped Python 3.4 support

0.22.0
------

* A lot of maintenance work (tooling, typing coverage and improvements, spelling) done, thanks to Ville Skyttä
* Provided saner defaults in ServiceInfo's constructor, thanks to Jorge Miranda
* Fixed service removal packets not being sent on shutdown, thanks to Andrew Bonney
* Added a way to define TTL-s through ServiceInfo contructor parameters, thanks to Andrew Bonney

Technically backwards incompatible:

* Adjusted query intervals to match RFC 6762, thanks to Andrew Bonney
* Made default TTL-s match RFC 6762, thanks to Andrew Bonney


0.21.3
------

* This time really allowed incoming service names to contain underscores (patch released
  as part of 0.21.0 was defective)

0.21.2
------

* Fixed import-time typing-related TypeError when older typing version is used

0.21.1
------

* Fixed installation on Python 3.4 (we use typing now but there was no explicit dependency on it)

0.21.0
------

* Added an error message when importing the package using unsupported Python version
* Fixed TTL handling for published service
* Implemented unicast support
* Fixed WSL (Windows Subsystem for Linux) compatibility
* Fixed occasional UnboundLocalError issue
* Fixed UTF-8 multibyte name compression
* Switched from netifaces to ifaddr (pure Python)
* Allowed incoming service names to contain underscores

0.20.0
------

* Dropped support for Python 2 (this includes PyPy) and 3.3
* Fixed some class' equality operators
* ServiceBrowser entries are being refreshed when 'stale' now
* Cache returns new records first now instead of last

0.19.1
------

* Allowed installation with netifaces >= 0.10.6 (a bug that was concerning us
  got fixed)

0.19.0
------

* Technically backwards incompatible - restricted netifaces dependency version to
  work around a bug, see https://github.com/jstasiak/python-zeroconf/issues/84 for
  details

0.18.0
------

* Dropped Python 2.6 support
* Improved error handling inside code executed when Zeroconf object is being closed

0.17.7
------

* Better Handling of DNS Incoming Packets parsing exceptions
* Many exceptions will now log a warning the first time they are seen
* Catch and log sendto() errors
* Fix/Implement duplicate name change
* Fix overly strict name validation introduced in 0.17.6
* Greatly improve handling of oversized packets including:

  - Implement name compression per RFC1035
  - Limit size of generated packets to 9000 bytes as per RFC6762
  - Better handle over sized incoming packets

* Increased test coverage to 95%

0.17.6
------

* Many improvements to address race conditions and exceptions during ZC()
  startup and shutdown, thanks to: morpav, veawor, justingiorgi, herczy,
  stephenrauch
* Added more test coverage: strahlex, stephenrauch
* Stephen Rauch contributed:

  - Speed up browser startup
  - Add ZeroconfServiceTypes() query class to discover all advertised service types
  - Add full validation for service names, types and subtypes
  - Fix for subtype browsing
  - Fix DNSHInfo support

0.17.5
------

* Fixed OpenBSD compatibility, thanks to Alessio Sergi
* Fixed race condition on ServiceBrowser startup, thanks to gbiddison
* Fixed installation on some Python 3 systems, thanks to Per Sandström
* Fixed "size change during iteration" bug on Python 3, thanks to gbiddison

0.17.4
------

* Fixed support for Linux kernel versions < 3.9 (thanks to Giovanni Harting
  and Luckydonald, GitHub pull request #26)

0.17.3
------

* Fixed DNSText repr on Python 3 (it'd crash when the text was longer than
  10 bytes), thanks to Paulus Schoutsen for the patch, GitHub pull request #24

0.17.2
------

* Fixed installation on Python 3.4.3+ (was failing because of enum34 dependency
  which fails to install on 3.4.3+, changed to depend on enum-compat instead;
  thanks to Michael Brennan for the original patch, GitHub pull request #22)

0.17.1
------

* Fixed EADDRNOTAVAIL when attempting to use dummy network interfaces on Windows,
  thanks to daid

0.17.0
------

* Added some Python dependencies so it's not zero-dependencies anymore
* Improved exception handling (it'll be quieter now)
* Messages are listened to and sent using all available network interfaces
  by default (configurable); thanks to Marcus Müller
* Started using logging more freely
* Fixed a bug with binary strings as property values being converted to False
  (https://github.com/jstasiak/python-zeroconf/pull/10); thanks to Dr. Seuss
* Added new ``ServiceBrowser`` event handler interface (see the examples)
* PyPy3 now officially supported
* Fixed ServiceInfo repr on Python 3, thanks to Yordan Miladinov

0.16.0
------

* Set up Python logging and started using it
* Cleaned up code style (includes migrating from camel case to snake case)

0.15.1
------

* Fixed handling closed socket (GitHub #4)

0.15
----

* Forked by Jakub Stasiak
* Made Python 3 compatible
* Added setup script, made installable by pip and uploaded to PyPI
* Set up Travis build
* Reformatted the code and moved files around
* Stopped catching BaseException in several places, that could hide errors
* Marked threads as daemonic, they won't keep application alive now

0.14
----

* Fix for SOL_IP undefined on some systems - thanks Mike Erdely.
* Cleaned up examples.
* Lowercased module name.

0.13
----

* Various minor changes; see git for details.
* No longer compatible with Python 2.2. Only tested with 2.5-2.7.
* Fork by William McBrine.

0.12
----

* allow selection of binding interface
* typo fix - Thanks A. M. Kuchlingi
* removed all use of word 'Rendezvous' - this is an API change

0.11
----

* correction to comments for addListener method
* support for new record types seen from OS X
  - IPv6 address
  - hostinfo

* ignore unknown DNS record types
* fixes to name decoding
* works alongside other processes using port 5353 (e.g. on Mac OS X)
* tested against Mac OS X 10.3.2's mDNSResponder
* corrections to removal of list entries for service browser

0.10
----

* Jonathon Paisley contributed these corrections:

  - always multicast replies, even when query is unicast
  - correct a pointer encoding problem
  - can now write records in any order
  - traceback shown on failure
  - better TXT record parsing
  - server is now separate from name
  - can cancel a service browser
  
* modified some unit tests to accommodate these changes

0.09
----

* remove all records on service unregistration
* fix DOS security problem with readName

0.08
----

* changed licensing to LGPL

0.07
----

* faster shutdown on engine
* pointer encoding of outgoing names
* ServiceBrowser now works
* new unit tests

0.06
----
* small improvements with unit tests
* added defined exception types
* new style objects
* fixed hostname/interface problem
* fixed socket timeout problem
* fixed add_service_listener() typo bug
* using select() for socket reads
* tested on Debian unstable with Python 2.2.2

0.05
----

* ensure case insensitivty on domain names
* support for unicast DNS queries

0.04
----

* added some unit tests
* added __ne__ adjuncts where required
* ensure names end in '.local.'
* timeout on receiving socket for clean shutdown


License
=======

LGPL, see COPYING file for details.
