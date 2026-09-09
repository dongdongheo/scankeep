# Security Policy

## Supported versions

Security fixes are applied to the latest revision on the default development
branch. Older revisions are not maintained unless a release explicitly states
otherwise.

## Reporting a vulnerability

Do not disclose suspected vulnerabilities in a public issue. Use the
repository's private vulnerability reporting form under **Security >
Advisories > Report a vulnerability**. If that form is unavailable, contact
the maintainer privately through the contact method on their GitHub profile.
Include:

- the affected revision;
- reproduction steps;
- expected impact;
- relevant logs with credentials and private data removed.

Operators should immediately run `deployment/rotate-access-token.sh` if the
Scankeep access token may have been exposed. Rotate the Fernet encryption key
only through a planned credential migration; replacing it directly makes
stored credentials unreadable.

## Deployment responsibility

Production operators are responsible for TLS termination, host and container
patching, access control, backups, secret custody, network policy, log
retention, and SonarQube authorization. Scankeep supports SAST operations
but does not itself certify compliance.
