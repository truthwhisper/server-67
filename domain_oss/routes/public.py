from flask import Blueprint, redirect, render_template, request, session, url_for

from ..models import ManagedZone, Setting, User
from ..i18n import SUPPORTED_LOCALES


bp = Blueprint("public", __name__)


@bp.get("/")
def home():
    return render_template(
        "home.html",
        user_count=User.query.filter_by(is_active_account=True).count(),
        zone_count=ManagedZone.query.filter_by(enabled=True).count(),
        registration_enabled=Setting.get("registration_enabled", "1") == "1",
    )


@bp.get("/locale/<locale>")
def set_locale(locale):
    if locale in SUPPORTED_LOCALES:
        session["locale"] = locale
    target = request.args.get("next", "/")
    return redirect(target if target.startswith("/") and not target.startswith("//") else url_for("public.home"))
