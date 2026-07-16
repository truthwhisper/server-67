# DigitalPlat Domain OSS

[![AGPL-3.0 license badge](https://licenses.opensource.ngo/badges/AGPL-3.0-modern.svg)](https://licenses.opensource.ngo/docs/public-licenses/AGPL-3.0)

DigitalPlat Domain OSS is a self-hosted domain and DNS management platform. It provides a unified user and administrator experience for publishing domains, managing DNS records, connecting authoritative DNS providers, and operating a domain service on infrastructure you control.

## Features

- One-command local installation with a browser-based setup wizard
- SQLite by default, with MySQL support through `DATABASE_URL`
- User registration, login, account suspension, and per-user domain limits
- Integrated administrator pages for users, domains, settings, DNS providers, zones, jobs, webhooks, and audit events
- Role-based teams, user sessions, email verification, password recovery, and TOTP two-factor authentication
- Scoped and expiring API keys, a versioned REST API, OpenAPI discovery, and Prometheus metrics
- DNS record support for A, AAAA, CNAME, MX, TXT, SRV, CAA, and NS
- BIND updates through authenticated RFC 2136 and TSIG
- PowerDNS Authoritative Server API support
- Cloudflare API token support
- Cloudflare DNSSEC lifecycle management and secondary DNS health checks
- ACME DNS-01 challenge automation with automatic cleanup
- JSON record import/export, CSV administration exports, and a Terraform provider
- English, Spanish, Simplified Chinese, Traditional Chinese, Portuguese, French, Russian, and Japanese interfaces
- Encrypted DNS credentials, CSRF protection, rate limits, secure password hashing, strict browser headers, and conservative network defaults
- Durable DNS change jobs with retries, signed webhooks, optional SMTP delivery, and provider health reporting
- Docker and Docker Compose deployment with a dedicated background worker

## Quick start

Requires Python 3.11 or newer.

```bash
git clone https://github.com/DigitalPlatDev/Domain-OSS.git
cd Domain-OSS
./panel install
./panel start
```

Open <http://127.0.0.1:8080/setup/> and create the first administrator. Then open **Admin → DNS providers**, connect a provider, test it, and add a managed zone.

The server binds to `127.0.0.1` by default. For direct LAN testing only:

```bash
HOST=0.0.0.0 PORT=8080 ./panel start
```

For internet access, keep the local bind and place Caddy, nginx, or another HTTPS reverse proxy in front of the panel.

## Docker quick start

```bash
cp .env.example .env
```

Replace `SECRET_KEY` in `.env` with the output of `python3 -c 'import secrets; print(secrets.token_urlsafe(48))'`, then run:

```bash
docker compose up -d --build
```

The container is published only on `127.0.0.1:8080`. Complete setup through your reverse proxy or an SSH tunnel.

To use MySQL:

```bash
docker compose -f docker-compose.yml -f docker-compose.mysql.yml up -d --build
```

Set `MYSQL_PASSWORD` and `MYSQL_ROOT_PASSWORD` in `.env` first.

## DNS provider setup

### Cloudflare

Create an API token with `Zone:DNS:Edit` and `Zone:Zone:Read` for only the zone DigitalPlat Domain OSS will manage. Add the provider, then create a managed zone using the Cloudflare zone ID as **Remote zone ID**.

### PowerDNS

Enable the Authoritative Server HTTP API, restrict it to the DigitalPlat Domain OSS host, and use a dedicated API key. Enter the API root URL, such as `https://dns.example.org`, and the key. The remote zone ID is optional; DigitalPlat Domain OSS uses the fully qualified zone name by default.

### BIND

Configure a narrowly scoped TSIG key and permit RFC 2136 updates for the managed zone. Enter the update server, TCP port, key name, base64 secret, and algorithm. Restrict TCP port 53 so only the DigitalPlat Domain OSS host can reach the update service.

Example BIND policy:

```text
key "domain-oss-key" {
    algorithm hmac-sha256;
    secret "REPLACE_WITH_TSIG_SECRET";
};

zone "example.org" {
    type primary;
    file "db.example.org";
    update-policy {
        grant domain-oss-key zonesub ANY;
    };
};
```

Use a more restrictive `update-policy` when your BIND deployment supports a narrower rule for the delegated namespace.

## Configuration

| Variable | Default | Purpose |
| --- | --- | --- |
| `DATABASE_URL` | Local SQLite file | SQLAlchemy database URL; MySQL uses `mysql+pymysql://...` |
| `SECRET_KEY` | Persistent local file | Session signing and DNS credential encryption key |
| `SOURCE_URL` | Official GitHub repository | Public source and license link for network users |
| `COOKIE_SECURE` | `0` | Set to `1` when served exclusively over HTTPS |
| `HOST` | `127.0.0.1` | Bind address used by `./panel start` |
| `PORT` | `8080` | Web server port |
| `WORKERS` | `2` | Gunicorn worker count |

Do not change `SECRET_KEY` after storing provider credentials unless you first remove and recreate those providers. Back up the database and secret together.

## CLI

```text
./panel install       Create a virtual environment and initialize the database
./panel start         Start the production Gunicorn server
./panel doctor        Verify the database and basic runtime configuration
./panel create-admin  Create a recovery administrator from the terminal
./panel init-db       Create missing database tables
./panel upgrade       Apply versioned database migrations
./panel worker        Process DNS synchronization and ACME cleanup jobs
```

## Database backup

For the default installation, stop the panel briefly and back up both `instance/domain-oss.db` and `instance/secret_key`. With Docker, back up the `domain_oss_data` volume. Use your normal consistent snapshot or dump process for MySQL.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/ruff check .
```

The application factory is `domain_oss:create_app`. Templates and assets are server-rendered so the project stays easy to audit and deploy.

## REST API and automation

Create a scoped API key from **Account & security**. The OpenAPI document is available at `/api/v1/openapi.json`; API requests use `Authorization: Bearer dpo_...`. Keep keys in a secret manager and grant only the scopes required by the integration.

The Terraform provider source and example are in [`integrations/terraform-provider-domainoss`](integrations/terraform-provider-domainoss). ACME clients can publish and clean up DNS-01 challenges through the scoped challenge endpoints without receiving general account credentials.

Prometheus metrics are available at `/api/v1/metrics` to administrator API keys with the `admin:metrics` scope.

## Email and webhooks

Set `PUBLIC_ORIGIN` and the `SMTP_*` variables to enable password recovery and verification mail. When SMTP is not configured, the panel continues to operate and records a delivery warning.

Webhooks use an HMAC SHA-256 signature in `X-Domain-OSS-Signature`. HTTPS endpoints must resolve only to public addresses unless `ALLOW_PRIVATE_WEBHOOKS=1` is explicitly configured. Redirects are not followed.

See the [documentation index](docs/README.md) for installation, configuration, user, administrator, provider, automation, backup, testing, and production guidance.

## Security model and scope

Administrators choose which parent zones are available to users. A user can claim a single label below those zones and edit records only beneath the resulting domain. DNS credentials are protected administrator secrets and are never exposed to users.

DigitalPlat Domain OSS is not a registrar, registry, billing platform, abuse-handling service, or authoritative DNS server. DNSSEC controls are currently available through Cloudflare; BIND and PowerDNS installations continue to manage signing on their authoritative infrastructure. Operators remain responsible for HTTPS, backups, provider access policy, monitoring, abuse response, and applicable registration policies.

Read [SECURITY.md](SECURITY.md) before exposing an installation to the internet.

## License

Copyright (C) 2026 DigitalPlat Domain OSS contributors.

DigitalPlat Domain OSS is licensed under the GNU Affero General Public License, version 3 only. See [LICENSE](LICENSE). If you run a modified version as a network service, the license requires that users be offered the corresponding source code.
