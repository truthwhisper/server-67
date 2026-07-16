import pytest

from domain_oss import create_app
from domain_oss.extensions import db
from domain_oss.models import Setting, User


@pytest.fixture()
def app():
    app = create_app({
        "TESTING": True,
        "SECRET_KEY": "test-secret-key-that-is-long-and-stable",
        "SQLALCHEMY_DATABASE_URI": "sqlite:///:memory:",
        "WTF_CSRF_ENABLED": False,
    })
    with app.app_context():
        db.drop_all()
        db.create_all()
        admin = User(username="admin", email="admin@example.org", is_admin=True)
        admin.set_password("secure-password-123")
        db.session.add(admin)
        Setting.set("site_name", "Test Domains")
        Setting.set("registration_enabled", "1")
        Setting.set("max_domains_per_user", "3")
        db.session.commit()
    yield app


@pytest.fixture()
def client(app):
    return app.test_client()


def csrf(client):
    with client.session_transaction() as session:
        session["csrf_token"] = "test-csrf"
    return "test-csrf"


@pytest.fixture()
def admin_login(client):
    token = csrf(client)
    response = client.post("/login", data={
        "csrf_token": token,
        "identity": "admin",
        "password": "secure-password-123",
    })
    assert response.status_code == 302
    return token

