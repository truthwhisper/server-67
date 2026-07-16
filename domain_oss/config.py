import os
import secrets
from pathlib import Path


def _persistent_secret(instance_path: str) -> str:
    secret_file = Path(instance_path) / "secret_key"
    secret_file.parent.mkdir(parents=True, exist_ok=True)
    if secret_file.exists():
        return secret_file.read_text(encoding="utf-8").strip()
    value = secrets.token_urlsafe(48)
    secret_file.write_text(value, encoding="utf-8")
    secret_file.chmod(0o600)
    return value


def load_config(instance_path: str) -> dict:
    database_url = os.getenv("DATABASE_URL")
    if not database_url:
        instance = Path(instance_path)
        database_file = instance / "domain-oss.db"
        database_url = f"sqlite:///{database_file}"
    if database_url.startswith("mysql://"):
        database_url = database_url.replace("mysql://", "mysql+pymysql://", 1)
    return {
        "SECRET_KEY": os.getenv("SECRET_KEY") or _persistent_secret(instance_path),
        "SQLALCHEMY_DATABASE_URI": database_url,
        "SQLALCHEMY_TRACK_MODIFICATIONS": False,
        "MAX_CONTENT_LENGTH": 1 * 1024 * 1024,
        "SESSION_COOKIE_HTTPONLY": True,
        "SESSION_COOKIE_SAMESITE": "Lax",
        "SESSION_COOKIE_SECURE": os.getenv("COOKIE_SECURE", "0") == "1",
        "REMEMBER_COOKIE_HTTPONLY": True,
        "REMEMBER_COOKIE_SAMESITE": "Lax",
        "PERMANENT_SESSION_LIFETIME": 3600 * 12,
        "SOURCE_URL": os.getenv(
            "SOURCE_URL",
            "https://github.com/DigitalPlatDev/Domain-OSS",
        ),
        "PUBLIC_ORIGIN": os.getenv("PUBLIC_ORIGIN", "http://127.0.0.1:8080").rstrip("/"),
        "SMTP_HOST": os.getenv("SMTP_HOST", ""),
        "SMTP_PORT": int(os.getenv("SMTP_PORT", "587")),
        "SMTP_USERNAME": os.getenv("SMTP_USERNAME", ""),
        "SMTP_PASSWORD": os.getenv("SMTP_PASSWORD", ""),
        "SMTP_FROM": os.getenv("SMTP_FROM", "DigitalPlat Domain OSS <noreply@localhost>"),
        "SMTP_STARTTLS": os.getenv("SMTP_STARTTLS", "1") == "1",
        "WEBHOOK_TIMEOUT": float(os.getenv("WEBHOOK_TIMEOUT", "5")),
        "ALLOW_PRIVATE_WEBHOOKS": os.getenv("ALLOW_PRIVATE_WEBHOOKS", "0") == "1",
    }
