# Security Policy

## Reporting a vulnerability

Please report security vulnerabilities privately through GitHub's
[private vulnerability reporting][gh-report] for this repository.
That route sends the report directly to the maintainers and lets
us coordinate a fix, a CVE, and a release before public
disclosure.

**Do not** open a regular GitHub issue, a pull request, or post
to a public channel (mailing list, chat room, Stack Overflow,
etc.) for a suspected vulnerability. If you are unsure whether
something is a vulnerability, use the private report — we would
rather see a false alarm than a public one.

We aim to acknowledge new reports within a few business days.

[gh-report]: https://github.com/python-zeroconf/python-zeroconf/security/advisories/new

## Supported versions

Security fixes are released against the latest `0.x` line on
PyPI. Older releases are not maintained — please upgrade to the
current release before reporting, and confirm the issue still
reproduces there.

## Scope

`python-zeroconf` is an mDNS / DNS-SD library. By design it
parses untrusted multicast traffic from the local network
(RFC 6762, RFC 6763). In-scope issues include:

- Memory-safety, parsing, or denial-of-service issues triggered
  by crafted mDNS / DNS-SD packets reaching `DNSIncoming`, the
  record cache, the service registry, or listener callbacks.
- Logic bugs that cause the library to answer queries it should
  not, leak information across interfaces, or hijack a service
  name from another responder in a way the RFCs don't sanction.
- Issues in the build / packaging pipeline (`build_ext.py`,
  wheel contents, signed-release flow) that could lead to a
  compromised wheel on PyPI.

Out of scope:

- Risks inherent to running an mDNS responder on an untrusted
  network — mDNS is unauthenticated by design (RFC 6762 §21).
  Reports of the form "a malicious LAN peer can send packets"
  are expected behaviour unless they cross one of the lines
  above.
- Misconfiguration of a downstream application that uses the
  library.
