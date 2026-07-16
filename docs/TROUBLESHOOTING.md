# Troubleshooting

## Setup page does not appear

Check `./panel doctor`, confirm the process listens on the expected address, and open `/setup/` with the trailing slash. An installed instance redirects setup requests to the dashboard.

## Login is rejected

Confirm the account is active and use the username or email shown by the administrator. Check server time when TOTP codes fail. TOTP requires clocks on the server and authenticator device to agree.

## DNS record remains queued

Open **Administration → DNS jobs** and read the last error. Test the provider. Common causes are an expired token, a wrong PowerDNS zone identifier, a BIND TSIG mismatch, a blocked network port, or a zone policy that does not authorize the RRset. Keep `domain-oss worker` running.

## BIND returns NOTAUTH or REFUSED

Verify the zone is loaded as a primary, the TSIG key name and algorithm match exactly, the base64 secret is unchanged, and `update-policy` covers the delegated name and type. Query the same server and port configured in the panel.

## PowerDNS returns 404

Confirm the zone exists and that the remote ID is the zone name with a trailing dot unless the deployment uses a different identifier. The configured URL must be the API origin, not the full `/api/v1` path.

## Recovery email is missing

Check `SMTP_HOST`, port, credentials, STARTTLS policy, sender address, and `PUBLIC_ORIGIN`. Inspect SMTP logs. The recovery page intentionally returns the same message whether an email address exists or not.

## Webhook URL is rejected

Production webhooks must use HTTPS and resolve only to public addresses. Private and loopback targets require `ALLOW_PRIVATE_WEBHOOKS=1`, which is intended only for a controlled development environment.

## Encrypted data cannot be read

Restore the `SECRET_KEY` that belongs to the database. If it is permanently lost, remove and recreate provider and webhook configurations and re-enroll affected TOTP accounts.
