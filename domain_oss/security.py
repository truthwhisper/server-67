import base64
import hashlib
import json
import re
import secrets
import time
from collections import defaultdict, deque
from functools import wraps

from cryptography.fernet import Fernet, InvalidToken
from flask import abort, current_app, flash, redirect, request, session, url_for
from flask_login import current_user

from .extensions import db
from .models import AuditLog


USERNAME_RE = re.compile(r"^[a-zA-Z0-9][a-zA-Z0-9_.-]{2,31}$")
LABEL_RE = re.compile(r"^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$")
RECORD_NAME_RE = re.compile(r"^(?:@|\*|[a-z0-9_](?:[a-z0-9_.-]{0,251}[a-z0-9_])?)$", re.I)
ALLOWED_RECORD_TYPES = {"A", "AAAA", "CNAME", "MX", "TXT", "SRV", "CAA", "NS"}
_attempts = defaultdict(deque)


def csrf_token():
    token = session.get("csrf_token")
    if not token:
        token = secrets.token_urlsafe(32)
        session["csrf_token"] = token
    return token


def validate_csrf():
    expected = session.get("csrf_token", "")
    supplied = request.form.get("csrf_token") or request.headers.get("X-CSRF-Token", "")
    if not expected or not secrets.compare_digest(expected, supplied):
        abort(400, "Invalid CSRF token")


def cipher():
    digest = hashlib.sha256(current_app.config["SECRET_KEY"].encode()).digest()
    return Fernet(base64.urlsafe_b64encode(digest))


def encrypt_config(value: dict) -> str:
    return cipher().encrypt(json.dumps(value).encode()).decode()


def decrypt_config(value: str) -> dict:
    try:
        return json.loads(cipher().decrypt(value.encode()).decode())
    except (InvalidToken, ValueError, json.JSONDecodeError):
        raise RuntimeError("Provider credentials could not be decrypted") from None


def admin_required(view):
    @wraps(view)
    def wrapped(*args, **kwargs):
        if not current_user.is_authenticated:
            return redirect(url_for("auth.login", next=request.path))
        if not current_user.is_admin:
            abort(403)
        return view(*args, **kwargs)

    return wrapped


def rate_limited(bucket: str, limit=8, window=300):
    key = f"{bucket}:{request.remote_addr or 'unknown'}"
    now = time.monotonic()
    queue = _attempts[key]
    while queue and queue[0] < now - window:
        queue.popleft()
    if len(queue) >= limit:
        return True
    queue.append(now)
    return False


def audit(action, target=""):
    db.session.add(AuditLog(
        actor_id=current_user.id if current_user.is_authenticated else None,
        action=action,
        target=str(target)[:255],
        ip_address=(request.headers.get("X-Forwarded-For", request.remote_addr or "").split(",")[0].strip())[:64],
    ))


def require_password_strength(password):
    if len(password) < 12 or len(password) > 128:
        return "Password must contain 12 to 128 characters."
    if not any(c.isalpha() for c in password) or not any(c.isdigit() for c in password):
        return "Password must contain at least one letter and one number."
    return None


def safe_next_url(value):
    return value if value and value.startswith("/") and not value.startswith("//") else None


def deny(message, endpoint="dashboard.index"):
    flash(message, "error")
    return redirect(url_for(endpoint))
