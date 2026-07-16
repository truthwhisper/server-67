from flask import Blueprint, flash, redirect, render_template, request, session, url_for
from flask_login import current_user, login_user, logout_user

from ..extensions import db
from ..models import Setting, User, UserSession, now_utc
from ..notifications import emit_event
from ..security import USERNAME_RE, audit, rate_limited, require_password_strength, safe_next_url


bp = Blueprint("auth", __name__)


@bp.route("/login", methods=["GET", "POST"])
def login():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if request.method == "POST":
        if rate_limited("login"):
            flash("Too many sign-in attempts. Please wait a few minutes.", "error")
            return render_template("auth/login.html"), 429
        identity = request.form.get("identity", "").strip().lower()
        user = User.query.filter((User.username == identity) | (User.email == identity)).first()
        if not user or not user.check_password(request.form.get("password", "")):
            flash("The email, username, or password is incorrect.", "error")
        elif not user.is_active_account:
            flash("This account is disabled.", "error")
        else:
            if user.totp_enabled:
                session["preauth_user_id"] = user.id
                session["preauth_remember"] = request.form.get("remember") == "on"
                return redirect(url_for("account.two_factor_challenge"))
            login_user(user, remember=request.form.get("remember") == "on")
            login_session = UserSession(
                user=user,
                ip_address=(request.remote_addr or "")[:64],
                user_agent=request.headers.get("User-Agent", "")[:255],
            )
            db.session.add(login_session)
            db.session.flush()
            session["user_session_id"] = login_session.id
            user.last_login_at = now_utc()
            audit("auth.login", user.username)
            db.session.commit()
            return redirect(safe_next_url(request.args.get("next")) or url_for("dashboard.index"))
    return render_template("auth/login.html")


@bp.route("/register", methods=["GET", "POST"])
def register():
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))
    if Setting.get("registration_enabled", "1") != "1":
        flash("Public registration is currently closed.", "info")
        return redirect(url_for("auth.login"))
    if request.method == "POST":
        if rate_limited("register", limit=5, window=600):
            flash("Too many registration attempts. Please try again later.", "error")
            return render_template("auth/register.html"), 429
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        error = require_password_strength(password)
        if not USERNAME_RE.fullmatch(username):
            error = "Username must be 3 to 32 letters, numbers, dots, dashes, or underscores."
        elif "@" not in email or len(email) > 254:
            error = "Enter a valid email address."
        elif User.query.filter((User.username == username) | (User.email == email)).first():
            error = "That username or email is already in use."
        if error:
            flash(error, "error")
        else:
            user = User(username=username, email=email, locale=session.get("locale", "en-US"))
            user.set_password(password)
            db.session.add(user)
            db.session.flush()
            audit("auth.register", username)
            emit_event(
                "user.created",
                {"user_id": user.id, "username": user.username},
                [user],
                "Welcome to DigitalPlat Domain OSS",
                "Your account is ready. Verify your email and enable two-factor authentication from Account & security.",
            )
            db.session.commit()
            login_user(user)
            return redirect(url_for("dashboard.index"))
    return render_template("auth/register.html")


@bp.post("/logout")
def logout():
    if current_user.is_authenticated:
        active_session = db.session.get(UserSession, session.get("user_session_id"))
        if active_session:
            active_session.revoked_at = now_utc()
        audit("auth.logout", current_user.username)
        db.session.commit()
    logout_user()
    return redirect(url_for("public.home"))
