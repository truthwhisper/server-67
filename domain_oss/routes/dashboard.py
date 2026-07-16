from flask import Blueprint, render_template
from flask_login import current_user, login_required

from ..models import AuditLog, Domain, ManagedZone
from ..permissions import visible_domains_query


bp = Blueprint("dashboard", __name__, url_prefix="/dashboard")


@bp.get("/")
@login_required
def index():
    domains = visible_domains_query().order_by(Domain.created_at.desc()).all()
    activity = AuditLog.query.filter_by(actor_id=current_user.id).order_by(AuditLog.created_at.desc()).limit(6).all()
    return render_template(
        "dashboard.html",
        domains=domains,
        activity=activity,
        available_zones=ManagedZone.query.filter_by(enabled=True).count(),
        record_count=sum(len(domain.records) for domain in domains),
    )
