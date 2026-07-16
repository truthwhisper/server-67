import hashlib
import json
import secrets
from datetime import timedelta
from functools import wraps

from flask import Blueprint, Response, g, jsonify, request
from flask_login import current_user

from ..extensions import db
from ..jobs import enqueue_rrset, process_job
from ..models import ACMEChallenge, APIKey, DNSChangeJob, DNSRecord, Domain, ManagedZone, now_utc
from ..notifications import emit_event
from ..permissions import can_access_domain, visible_domains_query
from ..providers import DNSProviderError
from ..security import LABEL_RE, rate_limited
from ..services import sync_rrset, validate_record


bp = Blueprint("api", __name__, url_prefix="/api/v1")


def api_error(message, status=400):
    return jsonify({"error": {"message": message, "status": status}}), status


def require_scope(scope):
    def decorator(view):
        @wraps(view)
        def wrapped(*args, **kwargs):
            if rate_limited("api", limit=300, window=60):
                return api_error("Rate limit exceeded", 429)
            if current_user.is_authenticated:
                g.api_user = current_user
                g.api_scopes = {"*"} if current_user.is_admin else {
                    "domains:read", "domains:write", "dns:read", "dns:write", "acme:write"
                }
            else:
                header = request.headers.get("Authorization", "")
                raw = header.removeprefix("Bearer ").strip()
                if not raw.startswith("dpo_"):
                    return api_error("Authentication required", 401)
                digest = hashlib.sha256(raw.encode()).hexdigest()
                key = APIKey.query.filter_by(key_hash=digest, revoked_at=None).first()
                if not key or (key.expires_at and key.expires_at <= now_utc()) or not key.user.is_active:
                    return api_error("Invalid API key", 401)
                key.last_used_at = now_utc()
                db.session.commit()
                g.api_user = key.user
                g.api_scopes = set(key.scopes.split(","))
            if scope not in g.api_scopes and "*" not in g.api_scopes:
                return api_error("Insufficient scope", 403)
            return view(*args, **kwargs)
        return wrapped
    return decorator


def domain_for_user(domain_id, permission="read"):
    domain = db.session.get(Domain, domain_id)
    if not domain or not can_access_domain(domain, permission, g.api_user):
        return None
    return domain


def serialize_domain(domain):
    return {
        "id": domain.id, "name": domain.fqdn, "label": domain.label, "status": domain.status,
        "zone": domain.zone.name, "created_at": domain.created_at.isoformat() + "Z",
    }


def serialize_record(record):
    return {
        "id": record.id, "name": record.name, "type": record.record_type,
        "content": record.content, "ttl": record.ttl, "priority": record.priority,
    }


@bp.get("/openapi.json")
def openapi():
    return jsonify({
        "openapi": "3.1.0",
        "info": {"title": "DigitalPlat Domain OSS API", "version": "1.0.0"},
        "servers": [{"url": "/api/v1"}],
        "components": {"securitySchemes": {"bearerAuth": {"type": "http", "scheme": "bearer"}}},
        "security": [{"bearerAuth": []}],
        "paths": {
            "/domains": {"get": {"summary": "List domains"}, "post": {"summary": "Create a domain"}},
            "/domains/{domain_id}": {
                "get": {"summary": "Get a domain"}, "delete": {"summary": "Delete a domain"}
            },
            "/domains/{domain_id}/records": {
                "get": {"summary": "List DNS records"}, "post": {"summary": "Create a DNS record"}
            },
            "/domains/{domain_id}/records/{record_id}": {
                "patch": {"summary": "Update a DNS record"}, "delete": {"summary": "Delete a DNS record"}
            },
            "/domains/{domain_id}/acme-challenges": {
                "post": {"summary": "Publish an ACME DNS-01 challenge"}
            },
            "/domains/{domain_id}/acme-challenges/{challenge_token}": {
                "delete": {"summary": "Remove an ACME DNS-01 challenge"}
            },
        },
    })


@bp.route("/domains", methods=["GET", "POST"])
@require_scope("domains:read")
def domains_collection():
    if request.method == "GET":
        query = Domain.query if g.api_user.is_admin and request.args.get("all") == "1" else visible_domains_query(g.api_user)
        page = max(1, request.args.get("page", 1, type=int))
        per_page = max(1, min(100, request.args.get("per_page", 50, type=int)))
        items = query.order_by(Domain.id).paginate(page=page, per_page=per_page, error_out=False)
        return jsonify({
            "data": [serialize_domain(item) for item in items.items],
            "meta": {"page": page, "per_page": per_page, "total": items.total, "pages": items.pages},
        })
    if "domains:write" not in g.api_scopes and "*" not in g.api_scopes:
        return api_error("Insufficient scope", 403)
    data = request.get_json(silent=True) or {}
    label = str(data.get("label", "")).strip().lower()
    zone = db.session.get(ManagedZone, data.get("zone_id"))
    if (
        not LABEL_RE.fullmatch(label)
        or not zone
        or not zone.enabled
        or not zone.provider.enabled
        or zone.registration_mode == "closed"
    ):
        return api_error("Invalid label or zone")
    if not zone.minimum_label_length <= len(label) <= zone.maximum_label_length:
        return api_error("Domain label does not meet the zone length policy")
    if label in set(json.loads(zone.reserved_labels or "[]")):
        return api_error("Domain label is reserved", 409)
    limit = zone.max_domains_per_user
    if limit and Domain.query.filter_by(owner_id=g.api_user.id).count() >= limit and not g.api_user.is_admin:
        return api_error("Domain limit reached", 409)
    fqdn = f"{label}.{zone.name}"
    if Domain.query.filter_by(fqdn=fqdn).first():
        return api_error("Domain already exists", 409)
    status = "pending" if zone.registration_mode == "approval" and not g.api_user.is_admin else "active"
    domain = Domain(label=label, fqdn=fqdn, owner_id=g.api_user.id, zone=zone, status=status)
    db.session.add(domain)
    db.session.flush()
    emit_event(
        "domain.created",
        {"domain_id": domain.id, "name": fqdn, "status": status},
        [g.api_user],
        "Domain created",
        f"{fqdn} was created with status {status}.",
    )
    db.session.commit()
    return jsonify({"data": serialize_domain(domain)}), 201


@bp.route("/domains/<int:domain_id>", methods=["GET", "DELETE"])
@require_scope("domains:read")
def domain_item(domain_id):
    permission = "read" if request.method == "GET" else "manage"
    domain = domain_for_user(domain_id, permission)
    if not domain:
        return api_error("Domain not found", 404)
    if request.method == "GET":
        return jsonify({"data": serialize_domain(domain)})
    if "domains:write" not in g.api_scopes and "*" not in g.api_scopes:
        return api_error("Insufficient scope", 403)
    rrsets = {(record.name, record.record_type) for record in domain.records}
    try:
        for name, record_type in rrsets:
            sync_rrset(domain, name, record_type, clear=True)
    except DNSProviderError as exc:
        return api_error(f"DNS cleanup failed: {exc}", 502)
    db.session.delete(domain)
    db.session.commit()
    return "", 204


@bp.route("/domains/<int:domain_id>/records", methods=["GET", "POST"])
@require_scope("dns:read")
def records_collection(domain_id):
    domain = domain_for_user(domain_id, "read" if request.method == "GET" else "write")
    if not domain:
        return api_error("Domain not found", 404)
    if request.method == "GET":
        return jsonify({"data": [serialize_record(item) for item in domain.records]})
    if "dns:write" not in g.api_scopes and "*" not in g.api_scopes:
        return api_error("Insufficient scope", 403)
    data = request.get_json(silent=True) or {}
    values, error = validate_record(
        data.get("name", "@"), data.get("type", ""), data.get("content", ""),
        data.get("ttl", 300), data.get("priority"),
    )
    if error:
        return api_error(error)
    if values["record_type"] not in set(json.loads(domain.zone.allowed_record_types or "[]")):
        return api_error("Record type is disabled for this zone", 403)
    if values["name"] == "*" and not domain.zone.allow_wildcard:
        return api_error("Wildcard records are disabled for this zone", 403)
    conflicts = DNSRecord.query.filter_by(domain_id=domain.id, name=values["name"]).all()
    if (values["record_type"] == "CNAME" and conflicts) or any(
        item.record_type == "CNAME" for item in conflicts
    ):
        return api_error("CNAME records cannot share a name with other records", 409)
    record = DNSRecord(domain=domain, **values)
    db.session.add(record)
    db.session.flush()
    job = enqueue_rrset(domain, record.name, record.record_type)
    db.session.commit()
    process_job(job)
    return jsonify({"data": serialize_record(record), "job_id": job.id, "sync_status": job.status}), 201


@bp.route("/domains/<int:domain_id>/records/<int:record_id>", methods=["PATCH", "DELETE"])
@require_scope("dns:write")
def record_item(domain_id, record_id):
    domain = domain_for_user(domain_id, "write")
    record = db.session.get(DNSRecord, record_id)
    if not domain or not record or record.domain_id != domain.id:
        return api_error("Record not found", 404)
    old_name, old_type = record.name, record.record_type
    if request.method == "DELETE":
        db.session.delete(record)
        db.session.flush()
        job = enqueue_rrset(domain, old_name, old_type)
        db.session.commit()
        process_job(job)
        return "", 204
    data = request.get_json(silent=True) or {}
    values, error = validate_record(
        data.get("name", record.name), data.get("type", record.record_type),
        data.get("content", record.content), data.get("ttl", record.ttl),
        data.get("priority", record.priority),
    )
    if error:
        return api_error(error)
    if values["record_type"] not in set(json.loads(domain.zone.allowed_record_types or "[]")):
        return api_error("Record type is disabled for this zone", 403)
    if values["name"] == "*" and not domain.zone.allow_wildcard:
        return api_error("Wildcard records are disabled for this zone", 403)
    conflicts = DNSRecord.query.filter(
        DNSRecord.domain_id == domain.id,
        DNSRecord.name == values["name"],
        DNSRecord.id != record.id,
    ).all()
    if (values["record_type"] == "CNAME" and conflicts) or any(
        item.record_type == "CNAME" for item in conflicts
    ):
        return api_error("CNAME records cannot share a name with other records", 409)
    for name, value in values.items():
        setattr(record, name, value)
    db.session.flush()
    jobs = []
    if (old_name, old_type) != (record.name, record.record_type):
        jobs.append(enqueue_rrset(domain, old_name, old_type))
    jobs.append(enqueue_rrset(domain, record.name, record.record_type))
    db.session.commit()
    for job in jobs:
        process_job(job)
    return jsonify({"data": serialize_record(record), "jobs": [item.id for item in jobs]})


@bp.post("/domains/<int:domain_id>/acme-challenges")
@require_scope("acme:write")
def create_acme_challenge(domain_id):
    domain = domain_for_user(domain_id, "write")
    if not domain or domain.status != "active":
        return api_error("Active domain not found", 404)
    data = request.get_json(silent=True) or {}
    value = str(data.get("value", "")).strip()
    if not value or len(value) > 512:
        return api_error("A valid ACME challenge value is required")
    name = str(data.get("name", "_acme-challenge")).strip().lower()
    values, error = validate_record(name, "TXT", value, 120, None)
    if error:
        return api_error(error)
    if "TXT" not in set(json.loads(domain.zone.allowed_record_types or "[]")):
        return api_error("TXT records are disabled for this zone", 403)
    if DNSRecord.query.filter_by(domain_id=domain.id, name=name, record_type="CNAME").first():
        return api_error("The ACME record name is occupied by a CNAME", 409)
    raw_token = "acme_" + secrets.token_urlsafe(24)
    challenge = ACMEChallenge(
        domain=domain,
        token_hash=hashlib.sha256(raw_token.encode()).hexdigest(),
        record_name=name,
        record_value=value,
        expires_at=now_utc() + timedelta(hours=1),
    )
    record = DNSRecord(domain=domain, **values)
    db.session.add_all([challenge, record])
    db.session.flush()
    job = enqueue_rrset(domain, name, "TXT")
    db.session.commit()
    process_job(job)
    challenge.status = "published" if job.status == "completed" else "queued"
    db.session.commit()
    return jsonify({
        "data": {
            "token": raw_token,
            "name": f"{name}.{domain.fqdn}",
            "value": value,
            "expires_at": challenge.expires_at.isoformat() + "Z",
            "sync_status": job.status,
        }
    }), 201


@bp.delete("/domains/<int:domain_id>/acme-challenges/<challenge_token>")
@require_scope("acme:write")
def delete_acme_challenge(domain_id, challenge_token):
    domain = domain_for_user(domain_id, "write")
    digest = hashlib.sha256(challenge_token.encode()).hexdigest()
    challenge = ACMEChallenge.query.filter_by(domain_id=domain.id if domain else 0, token_hash=digest).first()
    if not domain or not challenge:
        return api_error("Challenge not found", 404)
    record = DNSRecord.query.filter_by(
        domain_id=domain.id,
        name=challenge.record_name,
        record_type="TXT",
        content=challenge.record_value,
    ).first()
    if record:
        db.session.delete(record)
    challenge.status = "cleaned"
    db.session.flush()
    job = enqueue_rrset(domain, challenge.record_name, "TXT")
    db.session.commit()
    process_job(job)
    return "", 204


@bp.get("/metrics")
@require_scope("admin:metrics")
def metrics():
    lines = [
        "# HELP domain_oss_domains_total Total managed domains",
        "# TYPE domain_oss_domains_total gauge",
        f"domain_oss_domains_total {Domain.query.count()}",
        "# HELP domain_oss_dns_jobs_total DNS jobs by status",
        "# TYPE domain_oss_dns_jobs_total gauge",
    ]
    for status in ("pending", "retrying", "completed", "failed"):
        lines.append(f'domain_oss_dns_jobs_total{{status="{status}"}} {DNSChangeJob.query.filter_by(status=status).count()}')
    return Response("\n".join(lines) + "\n", mimetype="text/plain; version=0.0.4")
