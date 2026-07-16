from pathlib import Path

from domain_oss import create_app
from domain_oss.extensions import db
from domain_oss.models import DNSProvider, Domain, ManagedZone, User
from domain_oss.security import encrypt_config

from .conftest import csrf


def test_instance_path_override(monkeypatch, tmp_path):
    monkeypatch.setenv("INSTANCE_PATH", str(tmp_path))
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "instance-path-test-secret-key-that-is-long-and-stable",
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    assert Path(app.instance_path) == tmp_path


def test_home_and_health(client):
    assert client.get("/").status_code == 200
    assert client.get("/healthz").json == {"status": "ok", "installed": True}


def test_csrf_is_required(client):
    response = client.post("/login", data={"identity": "admin", "password": "wrong"})
    assert response.status_code == 400


def test_registration_and_login(client, app):
    token = csrf(client)
    response = client.post("/register", data={
        "csrf_token": token,
        "username": "alice",
        "email": "alice@example.org",
        "password": "correct-horse-123",
    })
    assert response.status_code == 302
    with app.app_context():
        assert User.query.filter_by(username="alice").one().check_password("correct-horse-123")


def test_admin_can_add_cloudflare_provider(client, admin_login, app):
    response = client.post("/admin/dns", data={
        "csrf_token": admin_login,
        "name": "Cloudflare primary",
        "kind": "cloudflare",
        "api_token": "secret-token",
    })
    assert response.status_code == 302
    with app.app_context():
        provider = DNSProvider.query.one()
        assert provider.kind == "cloudflare"
        assert "secret-token" not in provider.encrypted_config


def test_domain_creation(client, admin_login, app):
    with app.app_context():
        provider = DNSProvider(
            name="Test provider",
            kind="cloudflare",
            encrypted_config=encrypt_config({"api_token": "test"}),
        )
        db.session.add(provider)
        db.session.flush()
        zone = ManagedZone(name="example.org", provider=provider, remote_id="zone-id")
        db.session.add(zone)
        db.session.commit()
        zone_id = zone.id
    response = client.post("/domains/", data={
        "csrf_token": admin_login,
        "label": "project",
        "zone_id": str(zone_id),
    })
    assert response.status_code == 302
    with app.app_context():
        assert Domain.query.filter_by(fqdn="project.example.org").one()
