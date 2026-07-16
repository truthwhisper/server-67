# Testing

## Automated checks

```bash
.venv/bin/pytest -q
.venv/bin/ruff check .
(cd integrations/terraform-provider-domainoss && go test ./...)
docker compose config --quiet
```

The Python suite covers setup, authentication, authorization, domain policy, record validation, API keys, API endpoints, provider contracts, encryption, sessions, teams, TOTP, webhooks, jobs, DNSSEC behavior, and security headers.

## Real backend environment

The isolated integration stack runs BIND 9, PowerDNS Authoritative Server, MySQL, and Mailpit on loopback-only high ports:

```bash
docker compose -f tests/integration/compose.yml up -d
.venv/bin/python tests/integration/run_backends.py
docker compose -f tests/integration/compose.yml down -v
```

The script performs a signed RFC 2136 update and authoritative query against BIND, creates and updates a PowerDNS zone through the HTTP API, queries PowerDNS over DNS, opens a real MySQL connection, and verifies SMTP receipt. The test records are removed after verification.

To verify application migrations against MySQL:

```bash
DATABASE_URL='mysql+pymysql://domainoss:integration-mysql-password@127.0.0.1:13316/domainoss' \
SECRET_KEY='integration-secret-key-with-more-than-thirty-two-characters' \
.venv/bin/domain-oss upgrade
```

## Browser test matrix

Use a fresh isolated SQLite database and example-only accounts. Test setup, registration, login, TOTP, password recovery, sessions, API keys, teams, domain lifecycle, every record type, import and export, zone approval, user suspension, provider health, job retry, webhook delivery, settings, audit, CSV exports, language switching, responsive layout, and browser console errors.

Cloudflare must not be tested against a production token. Use provider contract tests unless a dedicated disposable Cloudflare zone and restricted token are explicitly supplied.
