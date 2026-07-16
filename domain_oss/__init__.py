import os

from flask import Flask, redirect, render_template, request, session, url_for
from flask_login import current_user, logout_user

from .config import load_config
from .extensions import db, login_manager
from .models import Setting, User, UserSession, now_utc
from .security import csrf_token, validate_csrf
from .i18n import LOCALE_LABELS, SUPPORTED_LOCALES, get_locale, translate


def create_app(test_config=None):
    app = Flask(
        __name__,
        instance_relative_config=True,
        instance_path=os.getenv("INSTANCE_PATH"),
    )
    app.config.from_mapping(load_config(app.instance_path))
    if test_config:
        app.config.update(test_config)

    db.init_app(app)
    login_manager.init_app(app)

    from .routes import account, admin, api, auth, dashboard, domains, public, setup

    app.register_blueprint(public.bp)
    app.register_blueprint(auth.bp)
    app.register_blueprint(setup.bp)
    app.register_blueprint(dashboard.bp)
    app.register_blueprint(domains.bp)
    app.register_blueprint(admin.bp)
    app.register_blueprint(account.bp)
    app.register_blueprint(api.bp)

    @login_manager.user_loader
    def load_user(user_id):
        try:
            return db.session.get(User, int(user_id))
        except (TypeError, ValueError):
            return None

    @app.before_request
    def protect_request():
        endpoint = request.endpoint or ""
        if request.method == "POST" and not endpoint.startswith("api."):
            validate_csrf()
        if current_user.is_authenticated and not current_user.is_active:
            logout_user()
            return redirect(url_for("auth.login"))
        if current_user.is_authenticated:
            session_id = session.get("user_session_id")
            active_session = db.session.get(UserSession, session_id) if session_id else None
            if active_session and active_session.revoked_at:
                logout_user()
                session.clear()
                return redirect(url_for("auth.login"))
            if not active_session:
                active_session = UserSession(
                    user=current_user,
                    ip_address=(request.remote_addr or "")[:64],
                    user_agent=request.headers.get("User-Agent", "")[:255],
                )
                db.session.add(active_session)
                db.session.flush()
                session["user_session_id"] = active_session.id
                db.session.commit()
            elif (now_utc() - active_session.last_seen_at).total_seconds() > 300:
                active_session.last_seen_at = now_utc()
                db.session.commit()
        if (
            endpoint == "static"
            or endpoint.startswith("setup.")
            or endpoint == "public.set_locale"
            or endpoint == "health"
        ):
            return None
        if not User.query.filter_by(is_admin=True).first():
            return redirect(url_for("setup.wizard"))
        return None

    @app.after_request
    def security_headers(response):
        response.headers.setdefault("X-Content-Type-Options", "nosniff")
        response.headers.setdefault("X-Frame-Options", "DENY")
        response.headers.setdefault("Referrer-Policy", "strict-origin-when-cross-origin")
        response.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        response.headers.setdefault(
            "Content-Security-Policy",
            "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
            "connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'",
        )
        if request.is_secure:
            response.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response

    @app.context_processor
    def template_globals():
        site_name = Setting.get("site_name", "DigitalPlat Domain OSS")
        return {
            "csrf_token": csrf_token,
            "site_name": site_name,
            "source_url": app.config["SOURCE_URL"],
            "get_setting": Setting.get,
            "t": translate,
            "current_locale": get_locale(),
            "supported_locales": SUPPORTED_LOCALES,
            "locale_label": lambda value: LOCALE_LABELS.get(value, value),
        }

    @app.get("/healthz", endpoint="health")
    def health():
        return {"status": "ok", "installed": User.query.filter_by(is_admin=True).first() is not None}

    @app.errorhandler(400)
    @app.errorhandler(403)
    @app.errorhandler(404)
    @app.errorhandler(413)
    @app.errorhandler(500)
    def error_page(error):
        code = getattr(error, "code", 500)
        if code == 500:
            db.session.rollback()
        return render_template("error.html", code=code, message=getattr(error, "description", "Error")), code

    return app
