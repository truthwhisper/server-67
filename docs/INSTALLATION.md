# Installation

DigitalPlat Domain OSS requires Python 3.11 or later. SQLite is the default database and is suitable for a small installation. MySQL is recommended when the database must be managed separately or when multiple application processes share it.

## Local installation

```bash
git clone https://github.com/DigitalPlatDev/Domain-OSS.git
cd Domain-OSS
./panel install
./panel start
```

Open `http://127.0.0.1:8080/setup/`. Create the first administrator, choose the default per-user domain limit, and decide whether public registration is allowed.

![Initial setup wizard](screenshots/setup.jpg)

`./panel install` creates `.venv`, installs the application, and applies database migrations. The default SQLite database and persistent encryption secret are stored in `instance/`.

## Docker installation

```bash
cp .env.example .env
python3 -c 'import secrets; print(secrets.token_urlsafe(48))'
```

Put the generated value in `.env` as `SECRET_KEY`, then start the services:

```bash
docker compose up -d --build
docker compose ps
```

The published address is `127.0.0.1:8080`. The Compose project starts the panel and a DNS job worker. Data is stored in the `domain_oss_data` volume.

## MySQL with Docker

Set strong values for `MYSQL_PASSWORD` and `MYSQL_ROOT_PASSWORD` in `.env`, then run:

```bash
docker compose -f docker-compose.yml -f docker-compose.mysql.yml up -d --build
```

The MySQL override supplies `DATABASE_URL` to both the panel and worker. The database is not published to the host.

## Existing MySQL server

Create an empty UTF-8 database and a dedicated user, then set:

```text
DATABASE_URL=mysql+pymysql://domainoss:password@database.example.org/domainoss
```

Apply migrations before starting the service:

```bash
./panel upgrade
./panel doctor
```

## Reverse proxy

Keep the application on a private address and terminate HTTPS at Caddy, nginx, Apache, or another trusted proxy. Set `PUBLIC_ORIGIN` to the external URL and `COOKIE_SECURE=1`. Forward the original host and scheme headers. Limit the request body to 1 MiB or less.

## First DNS provider

After signing in, open **Administration → DNS providers**:

![DNS provider administration](screenshots/dns-providers.jpg)

1. Add BIND, PowerDNS, or Cloudflare credentials.
2. Use **Test** to verify connectivity.
3. Add a managed parent zone.
4. Open the zone policy and review registration, labels, record types, DNSSEC, and secondary server settings.
5. Register a test domain and publish a DNS record before onboarding users.
