from sqlalchemy import inspect, text

from .extensions import db
from .models import SchemaVersion


LATEST_SCHEMA_VERSION = 3


ADDITIVE_COLUMNS = {
    "user": {
        "role": "VARCHAR(24) NOT NULL DEFAULT 'member'",
        "locale": "VARCHAR(10) NOT NULL DEFAULT 'en-US'",
        "email_verified_at": "DATETIME NULL",
        "totp_secret_encrypted": "TEXT NULL",
        "totp_enabled": "BOOLEAN NOT NULL DEFAULT 0",
        "last_login_at": "DATETIME NULL",
    },
    "dns_provider": {
        "last_health_status": "VARCHAR(24) NOT NULL DEFAULT 'unknown'",
        "last_checked_at": "DATETIME NULL",
        "last_error": "TEXT NULL",
    },
    "managed_zone": {
        "registration_mode": "VARCHAR(24) NOT NULL DEFAULT 'open'",
        "max_domains_per_user": "INTEGER NULL",
        "reserved_labels": "TEXT NULL",
        "minimum_label_length": "INTEGER NOT NULL DEFAULT 1",
        "maximum_label_length": "INTEGER NOT NULL DEFAULT 63",
        "allowed_record_types": "TEXT NULL",
        "allow_wildcard": "BOOLEAN NOT NULL DEFAULT 1",
        "dnssec_status": "VARCHAR(24) NOT NULL DEFAULT 'unmanaged'",
        "secondary_dns": "TEXT NULL",
        "transfer_status": "VARCHAR(24) NOT NULL DEFAULT 'not_configured'",
    },
    "domain": {
        "team_id": "INTEGER NULL",
        "status": "VARCHAR(24) NOT NULL DEFAULT 'active'",
    },
    "dns_record": {
        "updated_at": "DATETIME NULL",
    },
}


def upgrade_database():
    inspector = inspect(db.engine)
    existing_tables = set(inspector.get_table_names())
    if not existing_tables:
        db.create_all()
    else:
        preparer = db.engine.dialect.identifier_preparer
        for table, columns in ADDITIVE_COLUMNS.items():
            if table not in existing_tables:
                continue
            existing_columns = {item["name"] for item in inspector.get_columns(table)}
            for name, definition in columns.items():
                if name not in existing_columns:
                    db.session.execute(text(
                        f"ALTER TABLE {preparer.quote(table)} ADD COLUMN {preparer.quote(name)} {definition}"
                    ))
        db.session.commit()
        db.create_all()
    version = SchemaVersion.query.order_by(SchemaVersion.id.desc()).first()
    if not version or version.version < LATEST_SCHEMA_VERSION:
        db.session.add(SchemaVersion(version=LATEST_SCHEMA_VERSION))
        db.session.commit()
    return LATEST_SCHEMA_VERSION
