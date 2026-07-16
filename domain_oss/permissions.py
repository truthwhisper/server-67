from flask import abort
from flask_login import current_user

from .extensions import db
from .models import Domain, TeamMember


WRITE_ROLES = {"owner", "operator", "member"}
MANAGE_ROLES = {"owner", "operator"}


def domain_role(domain, user=None):
    user = user or current_user
    if not getattr(user, "is_authenticated", False):
        return None
    if user.is_admin or domain.owner_id == user.id:
        return "owner"
    if not domain.team_id:
        return None
    membership = TeamMember.query.filter_by(team_id=domain.team_id, user_id=user.id).first()
    return membership.role if membership else None


def can_access_domain(domain, permission="read", user=None):
    role = domain_role(domain, user)
    if not role:
        return False
    if permission == "read":
        return True
    if permission == "write":
        return role in WRITE_ROLES
    if permission == "manage":
        return role in MANAGE_ROLES
    return False


def require_domain(domain_id, permission="read"):
    domain = db.session.get(Domain, domain_id)
    if not domain or not can_access_domain(domain, permission):
        abort(404)
    return domain


def visible_domains_query(user=None):
    user = user or current_user
    if user.is_admin:
        return Domain.query
    team_ids = db.session.query(TeamMember.team_id).filter(TeamMember.user_id == user.id)
    return Domain.query.filter((Domain.owner_id == user.id) | (Domain.team_id.in_(team_ids)))
