# Operations guide

## Production baseline

Run the panel behind an HTTPS reverse proxy, set `COOKIE_SECURE=1`, and set `PUBLIC_ORIGIN` to the public HTTPS URL. Keep the application bound to a private interface. Run one or more `domain-oss worker` processes so failed DNS writes and expired ACME challenges are processed.

Use a dedicated database account and a dedicated DNS credential. Provider tokens should be limited to configured zones. Restrict PowerDNS API and BIND RFC 2136 endpoints at the network layer.

## Upgrades

Back up the database and secret, update the source, install dependencies, and apply migrations:

```bash
git pull --ff-only
.venv/bin/pip install -e .
./panel upgrade
./panel doctor
```

Docker deployments apply migrations when the panel and worker start. Review release notes before updating a production installation.

## Backups

For SQLite, stop writes briefly and copy `instance/domain-oss.db` and `instance/secret_key` together. For MySQL, take a transactionally consistent database dump and preserve the configured `SECRET_KEY` in the same backup set. Test restores regularly.

## Monitoring

- Probe `/healthz` for process and installation status.
- Scrape `/api/v1/metrics` with an administrator key carrying `admin:metrics`.
- Review provider health, DNS jobs, notifications, webhook delivery, and the audit log in the administrator panel.
- Alert on failed DNS jobs and repeated provider health failures.

## Outbound delivery

Configure SMTP for password recovery and email verification. Configure signed HTTPS webhooks for domain and DNS job events. Private webhook targets are blocked unless explicitly enabled, and webhook redirects are never followed.

## Incident response

Revoke affected API keys and sessions from the account page. Rotate DNS provider credentials from the administrator panel. If the application secret is exposed, create a maintenance window, rotate the secret, and re-enter every encrypted provider, webhook, and two-factor secret.
