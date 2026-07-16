# Development

## Environment

```bash
python3 -m venv .venv
.venv/bin/pip install -e '.[dev]'
.venv/bin/pytest
.venv/bin/ruff check .
```

The Flask application factory is `domain_oss:create_app`. Routes are separated by public, setup, authentication, account, domain, administrator, and API concerns. Provider adapters implement the interface in `domain_oss/providers/base.py`.

## Database changes

Add versioned, idempotent migration logic in `domain_oss/migrations.py`. Test upgrades from the previous schema on both SQLite and MySQL. Never require operators to edit tables manually.

## Provider changes

Validate configuration without exposing secrets. Normalize record content in one place, use explicit timeouts, convert transport failures to `DNSProviderError`, and add contract tests. A provider test should be non-destructive; full write testing belongs in an isolated zone.

## Interface changes

Keep templates server-rendered and usable without client-side JavaScript. Preserve labels, keyboard focus, semantic tables, clear validation errors, responsive layouts, and English fallback strings. Follow [CONTENT_STYLE.md](CONTENT_STYLE.md).

## Pull request checks

Run unit tests, lint, the Terraform provider build, Compose validation, and the integration environment when changing DNS or database code. Do not include generated databases, runtime secrets, provider credentials, or user data.
