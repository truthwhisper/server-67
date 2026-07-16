import secrets
from datetime import UTC, datetime

from flask_login import UserMixin
from werkzeug.security import check_password_hash, generate_password_hash

from .extensions import db


def now_utc():
    return datetime.now(UTC).replace(tzinfo=None)


class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(32), unique=True, nullable=False, index=True)
    email = db.Column(db.String(254), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    is_admin = db.Column(db.Boolean, nullable=False, default=False)
    role = db.Column(db.String(24), nullable=False, default="member")
    is_active_account = db.Column(db.Boolean, nullable=False, default=True)
    locale = db.Column(db.String(10), nullable=False, default="en-US")
    email_verified_at = db.Column(db.DateTime, nullable=True)
    totp_secret_encrypted = db.Column(db.Text, nullable=True)
    totp_enabled = db.Column(db.Boolean, nullable=False, default=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    domains = db.relationship("Domain", back_populates="owner", cascade="all, delete-orphan")

    @property
    def is_active(self):
        return self.is_active_account

    def set_password(self, password):
        self.password_hash = generate_password_hash(password, method="scrypt")

    def check_password(self, password):
        return check_password_hash(self.password_hash, password)


class Setting(db.Model):
    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.Text, nullable=False, default="")

    @classmethod
    def get(cls, key, default=""):
        item = db.session.get(cls, key)
        return item.value if item else default

    @classmethod
    def set(cls, key, value):
        item = db.session.get(cls, key)
        if item:
            item.value = str(value)
        else:
            db.session.add(cls(key=key, value=str(value)))


class DNSProvider(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    kind = db.Column(db.String(24), nullable=False)
    encrypted_config = db.Column(db.Text, nullable=False)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    last_health_status = db.Column(db.String(24), nullable=False, default="unknown")
    last_checked_at = db.Column(db.DateTime, nullable=True)
    last_error = db.Column(db.Text, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    zones = db.relationship("ManagedZone", back_populates="provider")


class ManagedZone(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(253), unique=True, nullable=False, index=True)
    provider_id = db.Column(db.Integer, db.ForeignKey("dns_provider.id"), nullable=False)
    remote_id = db.Column(db.String(255), nullable=True)
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    registration_mode = db.Column(db.String(24), nullable=False, default="open")
    max_domains_per_user = db.Column(db.Integer, nullable=True)
    reserved_labels = db.Column(db.Text, nullable=False, default="[]")
    minimum_label_length = db.Column(db.Integer, nullable=False, default=1)
    maximum_label_length = db.Column(db.Integer, nullable=False, default=63)
    allowed_record_types = db.Column(
        db.Text, nullable=False, default='["A","AAAA","CNAME","MX","TXT","SRV","CAA","NS"]'
    )
    allow_wildcard = db.Column(db.Boolean, nullable=False, default=True)
    dnssec_status = db.Column(db.String(24), nullable=False, default="unmanaged")
    secondary_dns = db.Column(db.Text, nullable=False, default="[]")
    transfer_status = db.Column(db.String(24), nullable=False, default="not_configured")
    provider = db.relationship("DNSProvider", back_populates="zones")
    domains = db.relationship("Domain", back_populates="zone", cascade="all, delete-orphan")


class Domain(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    label = db.Column(db.String(63), nullable=False)
    fqdn = db.Column(db.String(253), unique=True, nullable=False, index=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    zone_id = db.Column(db.Integer, db.ForeignKey("managed_zone.id"), nullable=False)
    team_id = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=True)
    status = db.Column(db.String(24), nullable=False, default="active")
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    owner = db.relationship("User", back_populates="domains")
    zone = db.relationship("ManagedZone", back_populates="domains")
    team = db.relationship("Team", back_populates="domains")
    records = db.relationship("DNSRecord", back_populates="domain", cascade="all, delete-orphan")
    dns_jobs = db.relationship("DNSChangeJob", back_populates="domain", cascade="all, delete-orphan")
    acme_challenges = db.relationship("ACMEChallenge", back_populates="domain", cascade="all, delete-orphan")


class DNSRecord(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey("domain.id"), nullable=False)
    name = db.Column(db.String(253), nullable=False, default="@")
    record_type = db.Column(db.String(10), nullable=False)
    content = db.Column(db.Text, nullable=False)
    ttl = db.Column(db.Integer, nullable=False, default=300)
    priority = db.Column(db.Integer, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    updated_at = db.Column(db.DateTime, nullable=False, default=now_utc, onupdate=now_utc)
    domain = db.relationship("Domain", back_populates="records")


class AuditLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(80), nullable=False)
    target = db.Column(db.String(255), nullable=False, default="")
    ip_address = db.Column(db.String(64), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc, index=True)
    actor = db.relationship("User")


class SchemaVersion(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    version = db.Column(db.Integer, nullable=False, default=1)
    applied_at = db.Column(db.DateTime, nullable=False, default=now_utc)


class Team(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    slug = db.Column(db.String(80), unique=True, nullable=False, index=True)
    owner_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    owner = db.relationship("User", foreign_keys=[owner_id])
    members = db.relationship("TeamMember", back_populates="team", cascade="all, delete-orphan")
    domains = db.relationship("Domain", back_populates="team")


class TeamMember(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    team_id = db.Column(db.Integer, db.ForeignKey("team.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    role = db.Column(db.String(24), nullable=False, default="member")
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    team = db.relationship("Team", back_populates="members")
    user = db.relationship("User")
    __table_args__ = (db.UniqueConstraint("team_id", "user_id", name="uq_team_member_user"),)


class UserSession(db.Model):
    id = db.Column(db.String(64), primary_key=True, default=lambda: secrets.token_urlsafe(32))
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    ip_address = db.Column(db.String(64), nullable=False, default="")
    user_agent = db.Column(db.String(255), nullable=False, default="")
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    last_seen_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    revoked_at = db.Column(db.DateTime, nullable=True)
    user = db.relationship("User")


class APIKey(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False, index=True)
    name = db.Column(db.String(80), nullable=False)
    prefix = db.Column(db.String(16), nullable=False, index=True)
    key_hash = db.Column(db.String(64), nullable=False, unique=True)
    scopes = db.Column(db.Text, nullable=False, default="domains:read,dns:read")
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    last_used_at = db.Column(db.DateTime, nullable=True)
    expires_at = db.Column(db.DateTime, nullable=True)
    revoked_at = db.Column(db.DateTime, nullable=True)
    user = db.relationship("User")


class DNSChangeJob(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey("domain.id"), nullable=True, index=True)
    actor_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True)
    action = db.Column(db.String(40), nullable=False)
    payload = db.Column(db.Text, nullable=False, default="{}")
    status = db.Column(db.String(24), nullable=False, default="pending", index=True)
    attempts = db.Column(db.Integer, nullable=False, default=0)
    max_attempts = db.Column(db.Integer, nullable=False, default=5)
    last_error = db.Column(db.Text, nullable=True)
    run_after = db.Column(db.DateTime, nullable=False, default=now_utc, index=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    domain = db.relationship("Domain", back_populates="dns_jobs")
    actor = db.relationship("User")


class Notification(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=True, index=True)
    level = db.Column(db.String(16), nullable=False, default="info")
    event_type = db.Column(db.String(80), nullable=False)
    title = db.Column(db.String(160), nullable=False)
    body = db.Column(db.Text, nullable=False, default="")
    read_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc, index=True)
    user = db.relationship("User")


class WebhookEndpoint(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), nullable=False)
    url = db.Column(db.String(2048), nullable=False)
    encrypted_secret = db.Column(db.Text, nullable=False)
    events = db.Column(db.Text, nullable=False, default="*")
    enabled = db.Column(db.Boolean, nullable=False, default=True)
    last_status = db.Column(db.String(24), nullable=False, default="never")
    last_error = db.Column(db.Text, nullable=True)
    last_delivery_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)


class ACMEChallenge(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    domain_id = db.Column(db.Integer, db.ForeignKey("domain.id"), nullable=False, index=True)
    token_hash = db.Column(db.String(64), nullable=False, unique=True)
    record_name = db.Column(db.String(253), nullable=False)
    record_value = db.Column(db.Text, nullable=False)
    status = db.Column(db.String(24), nullable=False, default="pending")
    expires_at = db.Column(db.DateTime, nullable=False)
    created_at = db.Column(db.DateTime, nullable=False, default=now_utc)
    domain = db.relationship("Domain", back_populates="acme_challenges")
