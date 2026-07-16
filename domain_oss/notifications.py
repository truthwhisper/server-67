import hashlib
import hmac
import ipaddress
import json
import socket
from urllib.parse import urlparse

import requests
from flask import current_app

from .extensions import db
from .mail import send_email
from .models import Notification, User, WebhookEndpoint, now_utc
from .security import decrypt_config


def webhook_url_is_safe(url):
    parsed = urlparse(url)
    if parsed.username or parsed.password or not parsed.hostname:
        return False
    if parsed.scheme == "http":
        return parsed.hostname in {"127.0.0.1", "localhost", "::1"}
    if parsed.scheme != "https":
        return False
    if current_app.config.get("ALLOW_PRIVATE_WEBHOOKS"):
        return True
    try:
        addresses = socket.getaddrinfo(parsed.hostname, parsed.port or 443, type=socket.SOCK_STREAM)
    except OSError:
        return False
    return bool(addresses) and all(ipaddress.ip_address(item[4][0]).is_global for item in addresses)


def notify_user(user, event_type, title, body="", level="info", email=False):
    if not user:
        return None
    item = Notification(user=user, event_type=event_type, title=title, body=body, level=level)
    db.session.add(item)
    if email:
        send_email(user.email, title, body)
    return item


def emit_event(event_type, payload, users=None, title=None, body="", level="info", email=False):
    for user in users or []:
        notify_user(user, event_type, title or event_type, body, level, email)
    event = {
        "id": hashlib.sha256(f"{event_type}:{now_utc().isoformat()}".encode()).hexdigest()[:24],
        "type": event_type,
        "created_at": now_utc().isoformat() + "Z",
        "data": payload,
    }
    endpoints = WebhookEndpoint.query.filter_by(enabled=True).all()
    for endpoint in endpoints:
        events = {item.strip() for item in endpoint.events.split(",") if item.strip()}
        if "*" not in events and event_type not in events:
            continue
        deliver_webhook(endpoint, event)
    return event


def deliver_webhook(endpoint, event):
    if not webhook_url_is_safe(endpoint.url):
        endpoint.last_status = "blocked"
        endpoint.last_error = "Webhook URL must use HTTPS and resolve to public addresses"
        endpoint.last_delivery_at = now_utc()
        return False
    raw = json.dumps(event, separators=(",", ":"), sort_keys=True).encode()
    try:
        secret = decrypt_config(endpoint.encrypted_secret).get("secret", "").encode()
        signature = hmac.new(secret, raw, hashlib.sha256).hexdigest()
        response = requests.post(
            endpoint.url,
            data=raw,
            headers={
                "Content-Type": "application/json",
                "User-Agent": "DigitalPlat-Domain-OSS-Webhook/1.0",
                "X-Domain-OSS-Event": event["type"],
                "X-Domain-OSS-Signature": f"sha256={signature}",
            },
            timeout=float(current_app.config.get("WEBHOOK_TIMEOUT", 5)),
            allow_redirects=False,
        )
        response.raise_for_status()
        endpoint.last_status = "delivered"
        endpoint.last_error = None
    except (requests.RequestException, RuntimeError) as exc:
        endpoint.last_status = "failed"
        endpoint.last_error = str(exc)[:2000]
    endpoint.last_delivery_at = now_utc()
    return endpoint.last_status == "delivered"


def notify_admins(event_type, title, body="", level="info", payload=None):
    admins = User.query.filter_by(is_admin=True, is_active_account=True).all()
    return emit_event(event_type, payload or {}, admins, title, body, level)
