#!/usr/bin/env python3
"""Exercise the real BIND, PowerDNS, MySQL, and SMTP integration services."""

from __future__ import annotations

import smtplib
import time
from email.message import EmailMessage

import dns.resolver
import pymysql
import requests

from domain_oss.providers.base import RecordValue
from domain_oss.providers.bind import BindProvider
from domain_oss.providers.powerdns import PowerDNSProvider


def wait_for(label, check, timeout=90):
    deadline = time.monotonic() + timeout
    last_error = None
    while time.monotonic() < deadline:
        try:
            return check()
        except Exception as exc:  # Services need a short startup window.
            last_error = exc
            time.sleep(2)
    raise RuntimeError(f"{label} did not become ready: {last_error}")


def query_a(port, name):
    resolver = dns.resolver.Resolver(configure=False)
    resolver.nameservers = ["127.0.0.1"]
    resolver.port = port
    resolver.timeout = 2
    resolver.lifetime = 4
    return [str(item) for item in resolver.resolve(name, "A")]


def test_bind():
    provider = BindProvider({
        "server": "127.0.0.1",
        "port": 15353,
        "key_name": "domain-oss-key",
        "key_secret": "MDEyMzQ1Njc4OWFiY2RlZg==",
        "algorithm": "hmac-sha256",
    })
    provider.test()
    record = RecordValue(content="192.0.2.80", ttl=300, priority=None)
    provider.sync_rrset("bind.test", None, "panel.bind.test", "A", [record])
    assert query_a(15353, "panel.bind.test") == ["192.0.2.80"]
    provider.sync_rrset("bind.test", None, "panel.bind.test", "A", [])


def powerdns_request(method, path, **kwargs):
    return requests.request(
        method,
        f"http://127.0.0.1:18081/api/v1/servers/localhost{path}",
        headers={"X-API-Key": "integration-powerdns-key"},
        timeout=5,
        **kwargs,
    )


def test_powerdns():
    zone = powerdns_request("GET", "/zones/pdns.test.")
    if zone.status_code == 404:
        response = powerdns_request("POST", "/zones", json={
            "name": "pdns.test.",
            "kind": "Native",
            "nameservers": ["ns1.pdns.test."],
        })
        response.raise_for_status()
    else:
        zone.raise_for_status()

    provider = PowerDNSProvider({
        "api_url": "http://127.0.0.1:18081",
        "api_key": "integration-powerdns-key",
    })
    provider.test()
    record = RecordValue(content="192.0.2.81", ttl=300, priority=None)
    provider.sync_rrset("pdns.test", None, "panel.pdns.test", "A", [record])
    assert query_a(15354, "panel.pdns.test") == ["192.0.2.81"]
    provider.sync_rrset("pdns.test", None, "panel.pdns.test", "A", [])


def test_mysql():
    def connect():
        return pymysql.connect(
            host="127.0.0.1",
            port=13316,
            user="domainoss",
            password="integration-mysql-password",
            database="domainoss",
            connect_timeout=3,
        )

    connection = wait_for("MySQL", connect)
    with connection:
        with connection.cursor() as cursor:
            cursor.execute("SELECT 1")
            assert cursor.fetchone() == (1,)


def test_smtp():
    message = EmailMessage()
    message["From"] = "DigitalPlat Domain OSS <noreply@localhost>"
    message["To"] = "qa@example.test"
    message["Subject"] = "Integration test"
    message.set_content("SMTP delivery is working.")
    with smtplib.SMTP("127.0.0.1", 11025, timeout=5) as client:
        client.send_message(message)

    def message_received():
        response = requests.get("http://127.0.0.1:18025/api/v1/messages", timeout=5)
        response.raise_for_status()
        messages = response.json().get("messages", [])
        assert any(item.get("Subject") == "Integration test" for item in messages)
        return True

    wait_for("Mailpit message", message_received, timeout=20)


def main():
    wait_for("PowerDNS API", lambda: powerdns_request("GET", "").raise_for_status())
    wait_for("BIND", lambda: query_a(15353, "ns1.bind.test"))
    test_bind()
    test_powerdns()
    test_mysql()
    test_smtp()
    print("BIND, PowerDNS, MySQL, and SMTP integration checks passed.")


if __name__ == "__main__":
    main()
