import base64
import hashlib
import io
import re
import secrets
from datetime import timedelta

import pyotp
import segno
from flask import Blueprint, current_app, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_required, login_user

from ..extensions import db
from ..mail import send_email
from ..models import APIKey, Notification, Team, TeamMember, User, UserSession, now_utc
from ..security import audit, decrypt_config, encrypt_config, rate_limited, require_password_strength
from ..tokens import issue_token, read_token


bp = Blueprint("account", __name__, url_prefix="/account")
LOCALES = ("en-US", "zh-CN", "zh-TW", "es-ES", "pt-BR", "fr-FR", "ru-RU", "ja-JP")
SLUG_RE = re.compile(r"^[a-z0-9][a-z0-9-]{1,62}[a-z0-9]$")


def create_user_session(user):
    item = UserSession(
        user=user,
        ip_address=(request.remote_addr or "")[:64],
        user_agent=request.headers.get("User-Agent", "")[:255],
    )
    db.session.add(item)
    db.session.flush()
    session["user_session_id"] = item.id
    return item


@bp.get("/")
@login_required
def index():
    sessions = UserSession.query.filter_by(user_id=current_user.id).order_by(UserSession.last_seen_at.desc()).all()
    api_keys = APIKey.query.filter_by(user_id=current_user.id).order_by(APIKey.created_at.desc()).all()
    memberships = TeamMember.query.filter_by(user_id=current_user.id).all()
    notifications = Notification.query.filter_by(user_id=current_user.id).order_by(Notification.created_at.desc()).limit(25)
    return render_template(
        "account/index.html", sessions=sessions, api_keys=api_keys, memberships=memberships,
        notifications=notifications, locales=LOCALES,
    )


@bp.post("/preferences")
@login_required
def preferences():
    locale = request.form.get("locale", "en-US")
    if locale in LOCALES:
        current_user.locale = locale
        session["locale"] = locale
        db.session.commit()
        flash("Language preference saved.", "success")
    return redirect(url_for("account.index"))


@bp.post("/password")
@login_required
def change_password():
    password = request.form.get("password", "")
    error = require_password_strength(password)
    if not current_user.check_password(request.form.get("current_password", "")):
        error = "Current password is incorrect."
    if error:
        flash(error, "error")
    else:
        current_user.set_password(password)
        audit("account.password.change", current_user.username)
        db.session.commit()
        flash("Password updated.", "success")
    return redirect(url_for("account.index"))


@bp.route("/2fa/setup", methods=["GET", "POST"])
@login_required
def setup_2fa():
    secret = session.get("pending_totp_secret") or pyotp.random_base32()
    session["pending_totp_secret"] = secret
    uri = pyotp.TOTP(secret).provisioning_uri(name=current_user.email, issuer_name="DigitalPlat Domain OSS")
    output = io.BytesIO()
    segno.make(uri).save(output, kind="svg", scale=4)
    qr_data = base64.b64encode(output.getvalue()).decode()
    if request.method == "POST":
        if pyotp.TOTP(secret).verify(request.form.get("code", ""), valid_window=1):
            current_user.totp_secret_encrypted = encrypt_config({"secret": secret})
            current_user.totp_enabled = True
            session.pop("pending_totp_secret", None)
            audit("account.2fa.enable", current_user.username)
            db.session.commit()
            flash("Two-factor authentication enabled.", "success")
            return redirect(url_for("account.index"))
        flash("The verification code is invalid.", "error")
    return render_template("account/setup_2fa.html", secret=secret, qr_data=qr_data)


@bp.post("/2fa/disable")
@login_required
def disable_2fa():
    if not current_user.check_password(request.form.get("password", "")):
        flash("Password is incorrect.", "error")
    else:
        current_user.totp_enabled = False
        current_user.totp_secret_encrypted = None
        audit("account.2fa.disable", current_user.username)
        db.session.commit()
        flash("Two-factor authentication disabled.", "success")
    return redirect(url_for("account.index"))


@bp.route("/2fa/challenge", methods=["GET", "POST"])
def two_factor_challenge():
    user = db.session.get(User, session.get("preauth_user_id"))
    if not user or not user.totp_enabled:
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        secret = decrypt_config(user.totp_secret_encrypted)["secret"]
        if pyotp.TOTP(secret).verify(request.form.get("code", ""), valid_window=1):
            remember = bool(session.pop("preauth_remember", False))
            session.pop("preauth_user_id", None)
            login_user(user, remember=remember)
            create_user_session(user)
            user.last_login_at = now_utc()
            audit("auth.login.2fa", user.username)
            db.session.commit()
            return redirect(url_for("dashboard.index"))
        flash("The authentication code is invalid.", "error")
    return render_template("account/challenge_2fa.html")


@bp.post("/sessions/<session_id>/revoke")
@login_required
def revoke_session(session_id):
    item = db.session.get(UserSession, session_id)
    if item and item.user_id == current_user.id:
        item.revoked_at = now_utc()
        audit("account.session.revoke", session_id[:10])
        db.session.commit()
        flash("Session revoked.", "success")
    return redirect(url_for("account.index"))


@bp.post("/api-keys")
@login_required
def create_api_key():
    raw = "dpo_" + secrets.token_urlsafe(32)
    allowed_scopes = {"domains:read", "domains:write", "dns:read", "dns:write", "acme:write"}
    if current_user.is_admin:
        allowed_scopes.add("admin:metrics")
    selected_scopes = [scope for scope in request.form.getlist("scopes") if scope in allowed_scopes]
    scopes = ",".join(selected_scopes) or "domains:read,dns:read"
    try:
        expires_days = max(1, min(365, int(request.form.get("expires_days", "90"))))
    except ValueError:
        expires_days = 90
    item = APIKey(
        user=current_user, name=request.form.get("name", "API key").strip()[:80],
        prefix=raw[:12], key_hash=hashlib.sha256(raw.encode()).hexdigest(), scopes=scopes,
        expires_at=now_utc() + timedelta(days=expires_days),
    )
    db.session.add(item)
    audit("account.api_key.create", item.name)
    db.session.commit()
    flash(f"Copy this API key now; it will not be shown again: {raw}", "success")
    return redirect(url_for("account.index"))


@bp.post("/api-keys/<int:key_id>/revoke")
@login_required
def revoke_api_key(key_id):
    item = db.session.get(APIKey, key_id)
    if item and item.user_id == current_user.id:
        item.revoked_at = now_utc()
        audit("account.api_key.revoke", item.name)
        db.session.commit()
    return redirect(url_for("account.index"))


@bp.post("/teams")
@login_required
def create_team():
    name = request.form.get("name", "").strip()[:80]
    slug = request.form.get("slug", "").strip().lower()
    if not name or not SLUG_RE.fullmatch(slug) or Team.query.filter_by(slug=slug).first():
        flash("Enter a unique team name and slug.", "error")
    else:
        team = Team(name=name, slug=slug, owner=current_user)
        db.session.add(team)
        db.session.flush()
        db.session.add(TeamMember(team=team, user=current_user, role="owner"))
        audit("team.create", slug)
        db.session.commit()
        flash("Team created.", "success")
    return redirect(url_for("account.index"))


@bp.post("/teams/<int:team_id>/members")
@login_required
def add_team_member(team_id):
    team = db.session.get(Team, team_id)
    user = User.query.filter_by(email=request.form.get("email", "").strip().lower()).first()
    if not team or team.owner_id != current_user.id or not user:
        flash("Team or user not found.", "error")
    elif TeamMember.query.filter_by(team_id=team.id, user_id=user.id).first():
        flash("This user is already a team member.", "info")
    else:
        role = request.form.get("role", "member")
        if role not in {"operator", "member", "read_only"}:
            role = "member"
        db.session.add(TeamMember(team=team, user=user, role=role))
        audit("team.member.add", f"{team.slug}:{user.username}")
        db.session.commit()
        flash("Team member added.", "success")
    return redirect(url_for("account.index"))


@bp.post("/teams/<int:team_id>/members/<int:member_id>/role")
@login_required
def update_team_member(team_id, member_id):
    team = db.session.get(Team, team_id)
    membership = db.session.get(TeamMember, member_id)
    role = request.form.get("role", "member")
    if (
        not team
        or team.owner_id != current_user.id
        or not membership
        or membership.team_id != team.id
        or membership.user_id == team.owner_id
        or role not in {"operator", "member", "read_only"}
    ):
        flash("The team member could not be updated.", "error")
    else:
        membership.role = role
        audit("team.member.role", f"{team.slug}:{membership.user.username}:{role}")
        db.session.commit()
        flash("Team member role updated.", "success")
    return redirect(url_for("account.index"))


@bp.post("/teams/<int:team_id>/members/<int:member_id>/remove")
@login_required
def remove_team_member(team_id, member_id):
    team = db.session.get(Team, team_id)
    membership = db.session.get(TeamMember, member_id)
    if (
        not team
        or team.owner_id != current_user.id
        or not membership
        or membership.team_id != team.id
        or membership.user_id == team.owner_id
    ):
        flash("The team member could not be removed.", "error")
    else:
        username = membership.user.username
        db.session.delete(membership)
        audit("team.member.remove", f"{team.slug}:{username}")
        db.session.commit()
        flash("Team member removed.", "success")
    return redirect(url_for("account.index"))


@bp.post("/notifications/read")
@login_required
def read_notifications():
    Notification.query.filter_by(user_id=current_user.id, read_at=None).update({"read_at": now_utc()})
    db.session.commit()
    return redirect(url_for("account.index"))


@bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "POST" and not rate_limited("forgot-password", limit=5, window=600):
        user = User.query.filter_by(email=request.form.get("email", "").strip().lower()).first()
        if user:
            token = issue_token("password-reset", user.id, user.password_hash[-16:])
            link = f"{current_app.config['PUBLIC_ORIGIN']}{url_for('account.reset_password', token=token)}"
            send_email(user.email, "Reset your DigitalPlat Domain OSS password", f"Reset your password:\n\n{link}\n\nThis link expires in one hour.")
        flash("If the account exists, a recovery email has been sent.", "success")
    return render_template("account/forgot_password.html")


@bp.route("/reset-password/<token>", methods=["GET", "POST"])
def reset_password(token):
    data = read_token("password-reset", token, 3600)
    user = db.session.get(User, data["user_id"]) if data else None
    if not user or data["value"] != user.password_hash[-16:]:
        flash("This recovery link is invalid or expired.", "error")
        return redirect(url_for("account.forgot_password"))
    if request.method == "POST":
        error = require_password_strength(request.form.get("password", ""))
        if error:
            flash(error, "error")
        else:
            user.set_password(request.form["password"])
            UserSession.query.filter_by(user_id=user.id, revoked_at=None).update({"revoked_at": now_utc()})
            db.session.commit()
            flash("Password reset complete. Sign in with your new password.", "success")
            return redirect(url_for("auth.login"))
    return render_template("account/reset_password.html")


@bp.post("/verify-email/send")
@login_required
def send_verification():
    token = issue_token("verify-email", current_user.id, current_user.email)
    link = f"{current_app.config['PUBLIC_ORIGIN']}{url_for('account.verify_email', token=token)}"
    send_email(current_user.email, "Verify your DigitalPlat Domain OSS email", f"Verify your email:\n\n{link}\n\nThis link expires in 24 hours.")
    flash("Verification email requested.", "success")
    return redirect(url_for("account.index"))


@bp.get("/verify-email/<token>")
def verify_email(token):
    data = read_token("verify-email", token, 86400)
    user = db.session.get(User, data["user_id"]) if data else None
    if user and data["value"] == user.email:
        user.email_verified_at = now_utc()
        db.session.commit()
        flash("Email address verified.", "success")
    else:
        flash("The verification link is invalid or expired.", "error")
    return redirect(url_for("account.index") if current_user.is_authenticated else url_for("auth.login"))
