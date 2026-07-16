import json

from flask import Blueprint, abort, flash, jsonify, redirect, render_template, request, url_for
from flask_login import current_user, login_required

from ..extensions import db
from ..models import DNSRecord, Domain, ManagedZone, Setting, Team, TeamMember
from ..notifications import emit_event
from ..permissions import can_access_domain, require_domain, visible_domains_query
from ..providers import DNSProviderError
from ..security import LABEL_RE, audit
from ..services import sync_rrset, validate_record
from ..jobs import enqueue_rrset, process_job


bp = Blueprint("domains", __name__, url_prefix="/domains")


def owned_domain(domain_id, permission="read"):
    return require_domain(domain_id, permission)


@bp.route("/", methods=["GET", "POST"])
@login_required
def index():
    zones = ManagedZone.query.filter_by(enabled=True).order_by(ManagedZone.name).all()
    if request.method == "POST":
        label = request.form.get("label", "").strip().lower()
        try:
            zone_id = int(request.form.get("zone_id", ""))
        except ValueError:
            zone_id = 0
        zone = db.session.get(ManagedZone, zone_id)
        limit = zone.max_domains_per_user if zone and zone.max_domains_per_user else int(
            Setting.get("max_domains_per_user", "3")
        )
        limit = max(1, min(limit, 100))
        if Domain.query.filter_by(owner_id=current_user.id).count() >= limit and not current_user.is_admin:
            flash(f"Your account has reached its limit of {limit} domains.", "error")
        elif not LABEL_RE.fullmatch(label):
            flash("Use 1 to 63 lowercase letters, numbers, or interior dashes.", "error")
        elif not zone or not zone.enabled or not zone.provider.enabled:
            flash("Select an available domain zone.", "error")
        elif zone.registration_mode == "closed":
            flash("Registration is currently closed for this zone.", "error")
        elif not zone.minimum_label_length <= len(label) <= zone.maximum_label_length:
            flash(
                f"Names in this zone must contain {zone.minimum_label_length} to "
                f"{zone.maximum_label_length} characters.",
                "error",
            )
        elif label in set(json.loads(zone.reserved_labels or "[]")):
            flash("That name is reserved by the zone administrator.", "error")
        else:
            fqdn = f"{label}.{zone.name}"
            if Domain.query.filter_by(fqdn=fqdn).first():
                flash("That domain is already registered.", "error")
            else:
                status = "pending" if zone.registration_mode == "approval" and not current_user.is_admin else "active"
                domain = Domain(label=label, fqdn=fqdn, owner=current_user, zone=zone, status=status)
                db.session.add(domain)
                db.session.flush()
                audit("domain.create", fqdn)
                emit_event(
                    "domain.created",
                    {"domain_id": domain.id, "name": fqdn, "status": status},
                    [current_user],
                    "Domain created",
                    f"{fqdn} was created with status {status}.",
                )
                db.session.commit()
                flash(
                    "Domain submitted for approval." if status == "pending" else
                    "Domain created. Add a DNS record to point it to your service.",
                    "success",
                )
                return redirect(url_for("domains.detail", domain_id=domain.id))
    domains = visible_domains_query().order_by(Domain.created_at.desc()).all()
    return render_template("domains/index.html", domains=domains, zones=zones)


@bp.get("/<int:domain_id>")
@login_required
def detail(domain_id):
    domain = owned_domain(domain_id, "read")
    records = DNSRecord.query.filter_by(domain_id=domain.id).order_by(DNSRecord.name, DNSRecord.record_type).all()
    teams = (
        Team.query.join(TeamMember)
        .filter(TeamMember.user_id == current_user.id, TeamMember.role == "owner")
        .order_by(Team.name)
        .all()
    )
    return render_template(
        "domains/detail.html",
        domain=domain,
        records=records,
        teams=teams,
        can_write=can_access_domain(domain, "write"),
        can_manage=can_access_domain(domain, "manage"),
        allowed_types=set(json.loads(domain.zone.allowed_record_types or "[]")),
    )


@bp.post("/<int:domain_id>/records")
@login_required
def add_record(domain_id):
    domain = owned_domain(domain_id, "write")
    if domain.status != "active":
        flash("DNS changes are unavailable until this domain is active.", "error")
        return redirect(url_for("domains.detail", domain_id=domain.id))
    values, error = validate_record(
        request.form.get("name", "@"),
        request.form.get("record_type", ""),
        request.form.get("content", ""),
        request.form.get("ttl", "300"),
        request.form.get("priority"),
    )
    if error:
        flash(error, "error")
        return redirect(url_for("domains.detail", domain_id=domain.id))
    allowed_types = set(json.loads(domain.zone.allowed_record_types or "[]"))
    if values["record_type"] not in allowed_types:
        flash("This record type is disabled for the selected zone.", "error")
        return redirect(url_for("domains.detail", domain_id=domain.id))
    if values["name"] == "*" and not domain.zone.allow_wildcard:
        flash("Wildcard records are disabled for the selected zone.", "error")
        return redirect(url_for("domains.detail", domain_id=domain.id))
    conflicts = DNSRecord.query.filter_by(domain_id=domain.id, name=values["name"]).all()
    if values["record_type"] == "CNAME" and conflicts:
        flash("A CNAME cannot share a name with other records.", "error")
        return redirect(url_for("domains.detail", domain_id=domain.id))
    if any(item.record_type == "CNAME" for item in conflicts):
        flash("This name already has a CNAME record.", "error")
        return redirect(url_for("domains.detail", domain_id=domain.id))
    record = DNSRecord(domain=domain, **values)
    db.session.add(record)
    db.session.flush()
    job = enqueue_rrset(domain, record.name, record.record_type)
    audit("dns_record.create", f"{record.record_type} {record.name}.{domain.fqdn}")
    db.session.commit()
    if process_job(job):
        flash("DNS record published.", "success")
    else:
        flash("The record was saved and queued for automatic retry.", "info")
    return redirect(url_for("domains.detail", domain_id=domain.id))


@bp.post("/<int:domain_id>/records/<int:record_id>/delete")
@login_required
def delete_record(domain_id, record_id):
    domain = owned_domain(domain_id, "write")
    record = db.session.get(DNSRecord, record_id)
    if not record or record.domain_id != domain.id:
        abort(404)
    name, record_type = record.name, record.record_type
    audit("dns_record.delete", f"{record_type} {name}.{domain.fqdn}")
    db.session.delete(record)
    db.session.flush()
    job = enqueue_rrset(domain, name, record_type)
    db.session.commit()
    if process_job(job):
        flash("DNS record removed.", "success")
    else:
        flash("The record was removed locally and DNS cleanup is queued for retry.", "info")
    return redirect(url_for("domains.detail", domain_id=domain.id))


@bp.route("/<int:domain_id>/records/<int:record_id>/edit", methods=["GET", "POST"])
@login_required
def edit_record(domain_id, record_id):
    domain = owned_domain(domain_id, "write")
    record = db.session.get(DNSRecord, record_id)
    if not record or record.domain_id != domain.id:
        abort(404)
    if request.method == "GET":
        return render_template("domains/edit_record.html", domain=domain, record=record)
    values, error = validate_record(
        request.form.get("name", record.name),
        request.form.get("record_type", record.record_type),
        request.form.get("content", record.content),
        request.form.get("ttl", record.ttl),
        request.form.get("priority", record.priority),
    )
    if error:
        flash(error, "error")
        return redirect(url_for("domains.detail", domain_id=domain.id))
    if values["record_type"] not in set(json.loads(domain.zone.allowed_record_types or "[]")):
        flash("This record type is disabled for the selected zone.", "error")
        return redirect(url_for("domains.detail", domain_id=domain.id))
    if values["name"] == "*" and not domain.zone.allow_wildcard:
        flash("Wildcard records are disabled for the selected zone.", "error")
        return redirect(url_for("domains.detail", domain_id=domain.id))
    conflicts = DNSRecord.query.filter(
        DNSRecord.domain_id == domain.id,
        DNSRecord.name == values["name"],
        DNSRecord.id != record.id,
    ).all()
    if (values["record_type"] == "CNAME" and conflicts) or any(
        item.record_type == "CNAME" for item in conflicts
    ):
        flash("A CNAME cannot share a name with other records.", "error")
        return redirect(url_for("domains.detail", domain_id=domain.id))
    old_rrset = (record.name, record.record_type)
    for key, value in values.items():
        setattr(record, key, value)
    db.session.flush()
    jobs = []
    if old_rrset != (record.name, record.record_type):
        jobs.append(enqueue_rrset(domain, old_rrset[0], old_rrset[1]))
    jobs.append(enqueue_rrset(domain, record.name, record.record_type))
    audit("dns_record.update", f"{record.record_type} {record.name}.{domain.fqdn}")
    db.session.commit()
    success = all(process_job(job) for job in jobs)
    flash("DNS record updated." if success else "Record saved; synchronization is queued for retry.",
          "success" if success else "info")
    return redirect(url_for("domains.detail", domain_id=domain.id))


@bp.get("/<int:domain_id>/tools")
@login_required
def tools(domain_id):
    return render_template("domains/tools.html", domain=owned_domain(domain_id, "read"))


@bp.get("/<int:domain_id>/export")
@login_required
def export_records(domain_id):
    domain = owned_domain(domain_id, "read")
    payload = {
        "domain": domain.fqdn,
        "records": [
            {"name": item.name, "type": item.record_type, "content": item.content,
             "ttl": item.ttl, "priority": item.priority}
            for item in domain.records
        ],
    }
    response = jsonify(payload)
    response.headers["Content-Disposition"] = f'attachment; filename="{domain.fqdn}.json"'
    return response


@bp.post("/<int:domain_id>/import")
@login_required
def import_records(domain_id):
    domain = owned_domain(domain_id, "write")
    try:
        payload = json.loads(request.form.get("records_json", ""))
        items = payload.get("records", payload) if isinstance(payload, dict) else payload
        if not isinstance(items, list) or len(items) > 500:
            raise ValueError
    except (ValueError, json.JSONDecodeError):
        flash("Enter a valid JSON export containing no more than 500 records.", "error")
        return redirect(url_for("domains.detail", domain_id=domain.id))
    rrsets = set()
    added = 0
    for item in items:
        values, error = validate_record(
            item.get("name", "@"), item.get("type", ""), item.get("content", ""),
            item.get("ttl", 300), item.get("priority"),
        )
        if error:
            continue
        db.session.add(DNSRecord(domain=domain, **values))
        rrsets.add((values["name"], values["record_type"]))
        added += 1
    db.session.flush()
    jobs = [enqueue_rrset(domain, name, record_type) for name, record_type in rrsets]
    audit("dns_record.import", f"{domain.fqdn}: {added} records")
    db.session.commit()
    for job in jobs:
        process_job(job)
    flash(f"Imported {added} records.", "success")
    return redirect(url_for("domains.detail", domain_id=domain.id))


@bp.post("/<int:domain_id>/delete")
@login_required
def delete_domain(domain_id):
    domain = owned_domain(domain_id, "manage")
    rrsets = {(record.name, record.record_type) for record in domain.records}
    try:
        for name, record_type in rrsets:
            sync_rrset(domain, name, record_type, clear=True)
    except DNSProviderError as exc:
        db.session.rollback()
        flash(f"The domain was not removed because DNS cleanup failed: {exc}", "error")
    else:
        audit("domain.delete", domain.fqdn)
        db.session.delete(domain)
        db.session.commit()
        flash("Domain and its DNS records were removed.", "success")
    return redirect(url_for("domains.index"))


@bp.post("/<int:domain_id>/team")
@login_required
def assign_team(domain_id):
    domain = owned_domain(domain_id, "manage")
    if domain.owner_id != current_user.id and not current_user.is_admin:
        abort(404)
    team_id = request.form.get("team_id", type=int)
    if not team_id:
        domain.team_id = None
        audit("domain.team.remove", domain.fqdn)
        db.session.commit()
        flash("Team access removed.", "success")
        return redirect(url_for("domains.detail", domain_id=domain.id))
    team = db.session.get(Team, team_id)
    membership = TeamMember.query.filter_by(team_id=team_id, user_id=current_user.id).first()
    if not team or (not current_user.is_admin and (not membership or membership.role != "owner")):
        abort(404)
    domain.team = team
    audit("domain.team.assign", f"{domain.fqdn}:{team.slug}")
    db.session.commit()
    flash("Team access updated.", "success")
    return redirect(url_for("domains.detail", domain_id=domain.id))
