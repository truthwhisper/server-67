# Configuration reference

## Environment variables

| Variable | Default | Description |
| --- | --- | --- |
| `DATABASE_URL` | SQLite in `instance/` | SQLAlchemy URL. `mysql://` is normalized to `mysql+pymysql://`. |
| `INSTANCE_PATH` | Repository `instance/` with `./panel` | Directory used for the default SQLite database and generated persistent secret. |
| `SECRET_KEY` | Generated persistent file | Signs sessions and derives encryption for provider credentials, webhooks, and TOTP secrets. |
| `SOURCE_URL` | Official GitHub repository | Source and license link shown to network users. |
| `PUBLIC_ORIGIN` | `http://127.0.0.1:8080` | Absolute origin used in verification and recovery links. |
| `COOKIE_SECURE` | `0` | Set to `1` when the public service uses HTTPS only. |
| `HOST` | `127.0.0.1` | Address used by `./panel start`. |
| `PORT` | `8080` | HTTP port used by `./panel start`. |
| `WORKERS` | `2` | Gunicorn web worker count. |
| `SMTP_HOST` | Empty | SMTP server. Empty disables outbound email delivery. |
| `SMTP_PORT` | `587` | SMTP port. |
| `SMTP_USERNAME` | Empty | Optional SMTP username. |
| `SMTP_PASSWORD` | Empty | Optional SMTP password. |
| `SMTP_FROM` | Local no-reply address | RFC 5322 sender used for application email. |
| `SMTP_STARTTLS` | `1` | Enable SMTP STARTTLS. Use `0` only on a trusted local connection. |
| `ALLOW_PRIVATE_WEBHOOKS` | `0` | Allow loopback and private webhook targets for controlled development environments. |
| `WEBHOOK_TIMEOUT` | `5` | Outbound webhook timeout in seconds. |

## Secret handling

Back up `SECRET_KEY` with the database. Losing it prevents decryption of DNS credentials, TOTP secrets, and webhook secrets. Do not rotate it in place. A planned rotation requires re-entering all encrypted values and asking users with TOTP enabled to enroll again.

Do not put real provider credentials in Compose files, source control, screenshots, or support requests. Use a deployment secret manager where available.

## Instance settings

Administrators can change the displayed site name, default domain quota, and public registration policy in **Administration → Settings**. A zone-specific quota overrides the instance default.

## Supported languages

The interface provides English (`en-US`), Spanish (`es-ES`), Simplified Chinese (`zh-CN`), Traditional Chinese (`zh-TW`), Portuguese (`pt-BR`), French (`fr-FR`), Russian (`ru-RU`), and Japanese (`ja-JP`). English is the fallback for untranslated or newly added messages.
