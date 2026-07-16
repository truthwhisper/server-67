from flask import Blueprint, flash, redirect, render_template, request, url_for

from ..extensions import db
from ..i18n import get_locale
from ..models import Setting, User
from ..security import USERNAME_RE, require_password_strength


bp = Blueprint("setup", __name__, url_prefix="/setup")


@bp.route("/", methods=["GET", "POST"])
def wizard():
    if User.query.filter_by(is_admin=True).first():
        return redirect(url_for("public.home"))
    if request.method == "POST":
        site_name = request.form.get("site_name", "").strip()[:80]
        username = request.form.get("username", "").strip().lower()
        email = request.form.get("email", "").strip().lower()
        password = request.form.get("password", "")
        error = require_password_strength(password)
        if not site_name:
            error = "Site name is required."
        elif not USERNAME_RE.fullmatch(username):
            error = "Enter a valid administrator username."
        elif "@" not in email or len(email) > 254:
            error = "Enter a valid administrator email."
        if error:
            flash(error, "error")
        else:
            admin = User(username=username, email=email, is_admin=True, role="admin", locale=get_locale())
            admin.set_password(password)
            db.session.add(admin)
            Setting.set("site_name", site_name)
            Setting.set("registration_enabled", "1" if request.form.get("registration_enabled") else "0")
            Setting.set("max_domains_per_user", request.form.get("max_domains_per_user", "3"))
            db.session.commit()
            flash("Setup is complete. Sign in to configure your DNS provider and zone.", "success")
            return redirect(url_for("auth.login"))
    return render_template("setup/wizard.html")
