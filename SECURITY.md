# Security Policy

## Supported Versions

CipherRescue is pre-release software. All security reports will be
addressed in the main development branch.

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Please report security vulnerabilities by email to the project maintainer.
Include:

1. A description of the vulnerability and its potential impact.
2. Steps to reproduce the issue.
3. Any suggested mitigations or patches.

You will receive an acknowledgement within 72 hours and a full response
within 14 days.

## Scope

Security reports are welcome for:

- WriteBlocker bypass vulnerabilities
- AuditLog integrity weaknesses
- Plugin sandboxing escapes
- Authentication bypass vectors
- Credential memory exposure
- Build pipeline integrity issues (supply chain)

## Out of Scope

- Vulnerabilities in upstream tools (cryptsetup, dislocker, VeraCrypt).
  Please report these to the respective upstream projects.
- Issues that require physical access beyond the defined threat model
  (see the technical specification).

## Disclosure Policy

We follow responsible disclosure. We will coordinate a disclosure timeline
with the reporter, typically 90 days from report to public disclosure.
