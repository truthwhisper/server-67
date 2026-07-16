# Security policy

## Supported versions

Security fixes are provided for the latest release on the default branch.

## Reporting a vulnerability

Please do not open a public issue for a suspected vulnerability. Use GitHub private vulnerability reporting for this repository. Include the affected version, reproduction steps, impact, and any suggested mitigation. Maintainers should acknowledge a complete report within seven days.

## Deployment expectations

- Put the panel behind an HTTPS reverse proxy and set `COOKIE_SECURE=1`.
- Use a unique, random `SECRET_KEY` and protect the `.env` file.
- Give DNS API tokens access only to the zones managed by DigitalPlat Domain OSS.
- Restrict PowerDNS and BIND update endpoints at the network layer.
- Back up the database and encryption secret together. Provider credentials cannot be recovered without the same secret.
- Run `./panel doctor` after configuration changes and keep dependencies updated.
- Run the DNS worker continuously so queued changes and expired ACME challenges are processed.
- Keep private webhook targets disabled unless the deployment specifically requires them.
- Use expiring, least-privilege API keys and revoke unused sessions.

## Security boundaries

Users never receive DNS provider credentials. Domain and DNS access is checked for the owner, administrator, or assigned team role on both web and API paths. Webhook secrets, TOTP secrets, and provider credentials are encrypted with the application secret.

The application does not terminate TLS or operate authoritative DNS. Production operators must provide HTTPS, network policy, database security, backups, dependency updates, and DNS provider hardening.
