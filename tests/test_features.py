import hashlib
import re
from pathlib import Path

from domain_oss import create_app
from domain_oss.extensions import db
from domain_oss.i18n import SUPPORTED_LOCALES, TRANSLATIONS
from domain_oss.models import APIKey, DNSProvider, DNSRecord, Domain, ManagedZone, Team, TeamMember, User
from domain_oss.notifications import webhook_url_is_safe
from domain_oss.security import encrypt_config

from .conftest import csrf


def create_zone():
    provider = DNSProvider(
        name="Test provider",
        kind="cloudflare",
        encrypted_config=encrypt_config({"api_token": "test"}),
    )
    db.session.add(provider)
    db.session.flush()
    zone = ManagedZone(name="example.org", provider=provider, remote_id="zone-id")
    db.session.add(zone)
    db.session.flush()
    return zone


def test_supported_locales_match_product_languages():
    assert SUPPORTED_LOCALES == (
        "en-US", "zh-CN", "zh-TW", "es-ES", "pt-BR", "fr-FR", "ru-RU", "ja-JP"
    )


def test_spanish_covers_every_translated_template_string():
    keys = set()
    for template in Path("domain_oss/templates").rglob("*.html"):
        keys.update(re.findall(r"\bt\(['\"]([^'\"]+)['\"]\)", template.read_text()))
    assert keys <= TRANSLATIONS["es-ES"].keys()


def test_public_language_selector_uses_spanish(client):
    response = client.get("/locale/es-ES?next=/")
    assert response.status_code == 302
    page = client.get("/")
    assert b"Funciones" in page.data
    assert b'<html lang="es-ES">' in page.data


def test_setup_language_selector_works_before_installation():
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "uninstalled-test-secret-key-that-is-long-and-stable",
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
    })
    with app.app_context():
        db.drop_all()
        db.create_all()
    client = app.test_client()
    response = client.get("/locale/es-ES?next=/setup/")
    assert response.status_code == 302
    page = client.get("/setup/")
    assert b"Configura esta instalaci" in page.data
    assert b'<html lang="es-ES">' in page.data


def test_private_webhook_targets_are_blocked(app):
    with app.app_context():
        assert webhook_url_is_safe("http://localhost:9000/hook")
        assert not webhook_url_is_safe("https://127.0.0.1/hook")
        assert not webhook_url_is_safe("file:///tmp/hook")


def test_team_read_only_member_cannot_change_dns(client, app):
    with app.app_context():
        owner = User(username="owner", email="owner@example.org")
        owner.set_password("owner-password-123")
        reader = User(username="reader", email="reader@example.org")
        reader.set_password("reader-password-123")
        db.session.add_all([owner, reader])
        db.session.flush()
        team = Team(name="Documentation", slug="documentation", owner=owner)
        zone = create_zone()
        db.session.add_all([team, TeamMember(team=team, user=owner, role="owner")])
        db.session.flush()
        db.session.add(TeamMember(team=team, user=reader, role="read_only"))
        domain = Domain(label="docs", fqdn="docs.example.org", owner=owner, zone=zone, team=team)
        db.session.add(domain)
        db.session.commit()
        domain_id = domain.id
    token = csrf(client)
    assert client.post("/login", data={
        "csrf_token": token, "identity": "reader", "password": "reader-password-123"
    }).status_code == 302
    assert client.get(f"/domains/{domain_id}").status_code == 200
    response = client.post(f"/domains/{domain_id}/records", data={
        "csrf_token": token, "name": "@", "record_type": "A", "content": "192.0.2.1", "ttl": "300"
    })
    assert response.status_code == 404


def test_api_key_lists_and_reads_domains(client, app):
    raw_key = "dpo_test-key-for-api"
    with app.app_context():
        user = User(username="apiuser", email="api@example.org")
        user.set_password("api-password-123")
        zone = create_zone()
        db.session.add(user)
        db.session.flush()
        domain = Domain(label="api", fqdn="api.example.org", owner=user, zone=zone)
        key = APIKey(
            user=user,
            name="Test API",
            prefix=raw_key[:12],
            key_hash=hashlib.sha256(raw_key.encode()).hexdigest(),
            scopes="domains:read,dns:read",
        )
        db.session.add_all([domain, key])
        db.session.commit()
        domain_id = domain.id
    headers = {"Authorization": f"Bearer {raw_key}"}
    response = client.get("/api/v1/domains?per_page=10", headers=headers)
    assert response.status_code == 200
    assert response.json["meta"]["total"] == 1
    response = client.get(f"/api/v1/domains/{domain_id}", headers=headers)
    assert response.status_code == 200
    assert response.json["data"]["name"] == "api.example.org"


def test_admin_pages_render(client, admin_login):
    for path in ("/admin/users", "/admin/domains", "/admin/webhooks", "/account/"):
        assert client.get(path).status_code == 200


def test_json_and_csv_exports(client, app, admin_login):
    with app.app_context():
        admin = User.query.filter_by(username="admin").one()
        zone = create_zone()
        domain = Domain(label="export", fqdn="export.example.org", owner=admin, zone=zone)
        db.session.add(domain)
        db.session.flush()
        db.session.add(DNSRecord(
            domain=domain,
            name="@",
            record_type="A",
            content="192.0.2.44",
            ttl=300,
        ))
        db.session.commit()
        domain_id = domain.id

    records = client.get(f"/domains/{domain_id}/export")
    assert records.status_code == 200
    assert records.headers["Content-Disposition"] == 'attachment; filename="export.example.org.json"'
    assert records.get_json()["records"][0]["content"] == "192.0.2.44"

    users = client.get("/admin/users.csv")
    assert users.status_code == 200
    assert "domain-oss-users.csv" in users.headers["Content-Disposition"]
    assert b"admin@example.org" in users.data

    domains = client.get("/admin/domains.csv")
    assert domains.status_code == 200
    assert "domain-oss-domains.csv" in domains.headers["Content-Disposition"]
    assert b"export.example.org" in domains.data
