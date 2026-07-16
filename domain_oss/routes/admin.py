import json
import re
import secrets
import csv
import io

from flask import Blueprint, Response, flash, redirect, render_template, request, url_for
from flask_login import current_user

from ..extensions import db
from ..dns_tools import check_secondaries
from ..jobs import process_job
from ..models import (
    AuditLog,
    DNSChangeJob,
    DNSProvider,
    Domain,
    ManagedZone,
    Setting,
    User,
    WebhookEndpoint,
    now_utc,
)
from ..notifications import deliver_webhook, emit_event, webhook_url_is_safe
from ..providers import DNSProviderError, config_from_form, make_provider
from ..security import admin_required, audit, decrypt_config, encrypt_config


bp = Blueprint("admin", __name__, url_prefix="/admin")
ZONE_RE = re.compile(r"^(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}$")


@bp.get("/")
@admin_required
def index():
    return render_template(
        "management/index.html",
        users=User.query.count(),
        domains=Domain.query.count(),
        providers=DNSProvider.query.count(),
        zones=ManagedZone.query.count(),
        recent=AuditLog.query.order_by(AuditLog.created_at.desc()).limit(8).all(),
    )


@bp.route("/users", methods=["GET"])
@admin_required
def users():
    query_text = request.args.get("q", "").strip()
    query = User.query
    if query_text:
        pattern = f"%{query_text}%"
        query = query.filter((User.username.ilike(pattern)) | (User.email.ilike(pattern)))
    page = max(1, request.args.get("page", 1, type=int))
    users_page = query.order_by(User.created_at.desc()).paginate(page=page, per_page=50, error_out=False)
    return render_template("management/users.html", users=users_page, query=query_text)


@bp.post("/users/<int:user_id>/toggle")
@admin_required
def toggle_user(user_id):
    user = db.session.get(User, user_id)
    if not user:
        flash("User not found.", "error")
    elif user.id == current_user.id:
        flash("You cannot disable your own account.", "error")
    elif user.is_admin:
        flash("Administrator accounts cannot be disabled here.", "error")
    else:
        user.is_active_account = not user.is_active_account
        audit("admin.user.toggle", user.username)
        db.session.commit()
        flash("User status updated.", "success")
    return redirect(url_for("admin.users"))


@bp.post("/users/<int:user_id>/role")
@admin_required
def update_user_role(user_id):
    user = db.session.get(User, user_id)
    role = request.form.get("role", "member")
    if not user or role not in {"member", "admin"}:
        flash("Invalid user role.", "error")
    elif user.id == current_user.id and role != "admin":
        flash("You cannot remove your own administrator access.", "error")
    else:
        user.is_admin = role == "admin"
        user.role = role
        audit("admin.user.role", f"{user.username}:{role}")
        db.session.commit()
        flash("User role updated.", "success")
    return redirect(url_for("admin.users"))


@bp.get("/users.csv")
@admin_required
def export_users():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "username", "email", "role", "status", "domains", "created_at"])
    for user in User.query.order_by(User.id):
        writer.writerow([
            user.id, user.username, user.email, "admin" if user.is_admin else user.role,
            "active" if user.is_active_account else "suspended", len(user.domains), user.created_at.isoformat(),
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=domain-oss-users.csv"},
    )


@bp.route("/dns", methods=["GET", "POST"])
@admin_required
def dns():
    if request.method == "POST":
        kind = request.form.get("kind", "")
        name = request.form.get("name", "").strip()[:80]
        try:
            config = config_from_form(kind, request.form)
            if not name:
                raise DNSProviderError("Provider name is required")
            if DNSProvider.query.filter_by(name=name).first():
                raise DNSProviderError("A provider with this name already exists")
            provider = DNSProvider(name=name, kind=kind, encrypted_config=encrypt_config(config))
            db.session.add(provider)
            audit("admin.provider.create", name)
            db.session.commit()
            flash("DNS provider saved. Test it before adding a zone.", "success")
            return redirect(url_for("admin.dns"))
        except DNSProviderError as exc:
            flash(str(exc), "error")
    return render_template(
        "management/dns.html",
        providers=DNSProvider.query.order_by(DNSProvider.name).all(),
        zones=ManagedZone.query.order_by(ManagedZone.name).all(),
    )


@bp.post("/dns/providers/<int:provider_id>/test")
@admin_required
def test_provider(provider_id):
    provider = db.session.get(DNSProvider, provider_id)
    if not provider:
        flash("Provider not found.", "error")
    else:
        try:
            message = make_provider(provider.kind, decrypt_config(provider.encrypted_config)).test()
            provider.last_health_status = "healthy"
            provider.last_checked_at = now_utc()
            provider.last_error = None
            db.session.commit()
            flash(message, "success")
        except (DNSProviderError, RuntimeError) as exc:
            provider.last_health_status = "failed"
            provider.last_checked_at = now_utc()
            provider.last_error = str(exc)[:2000]
            db.session.commit()
            flash(str(exc), "error")
    return redirect(url_for("admin.dns"))


@bp.post("/dns/providers/<int:provider_id>/delete")
@admin_required
def delete_provider(provider_id):
    provider = db.session.get(DNSProvider, provider_id)
    if not provider:
        flash("Provider not found.", "error")
    elif provider.zones:
        flash("Remove this provider's zones first.", "error")
    else:
        audit("admin.provider.delete", provider.name)
        db.session.delete(provider)
        db.session.commit()
        flash("Provider removed.", "success")
    return redirect(url_for("admin.dns"))


@bp.route("/dns/providers/<int:provider_id>/edit", methods=["GET", "POST"])
@admin_required
def edit_provider(provider_id):
    provider = db.session.get(DNSProvider, provider_id)
    if not provider:
        flash("Provider not found.", "error")
        return redirect(url_for("admin.dns"))
    if request.method == "POST":
        provider.name = request.form.get("name", provider.name).strip()[:80] or provider.name
        provider.enabled = request.form.get("enabled") == "on"
        config = decrypt_config(provider.encrypted_config)
        fields = {
            "bind": ("server", "port", "key_name", "key_secret", "algorithm"),
            "powerdns": ("api_url", "api_key"),
            "cloudflare": ("api_token",),
        }[provider.kind]
        for field in fields:
            value = request.form.get(field, "").strip()
            if value:
                config[field] = value
        provider.encrypted_config = encrypt_config(config)
        audit("admin.provider.update", provider.name)
        db.session.commit()
        flash("Provider configuration updated.", "success")
        return redirect(url_for("admin.dns"))
    return render_template("management/provider_edit.html", provider=provider)


@bp.post("/dns/zones")
@admin_required
def add_zone():
    name = request.form.get("zone_name", "").strip().lower().rstrip(".")
    remote_id = request.form.get("remote_id", "").strip()[:255] or None
    try:
        provider_id = int(request.form.get("provider_id", ""))
    except ValueError:
        provider_id = 0
    provider = db.session.get(DNSProvider, provider_id)
    if not ZONE_RE.fullmatch(name):
        flash("Enter a valid DNS zone such as example.org.", "error")
    elif not provider or not provider.enabled:
        flash("Select an enabled DNS provider.", "error")
    elif ManagedZone.query.filter_by(name=name).first():
        flash("That DNS zone is already configured.", "error")
    else:
        db.session.add(ManagedZone(name=name, provider=provider, remote_id=remote_id))
        audit("admin.zone.create", name)
        db.session.commit()
        flash("Zone is ready for user domains.", "success")
    return redirect(url_for("admin.dns"))


@bp.post("/dns/zones/<int:zone_id>/delete")
@admin_required
def delete_zone(zone_id):
    zone = db.session.get(ManagedZone, zone_id)
    if not zone:
        flash("Zone not found.", "error")
    elif zone.domains:
        flash("A zone with registered domains cannot be removed.", "error")
    else:
        audit("admin.zone.delete", zone.name)
        db.session.delete(zone)
        db.session.commit()
        flash("Zone removed.", "success")
    return redirect(url_for("admin.dns"))


@bp.route("/dns/zones/<int:zone_id>/settings", methods=["GET", "POST"])
@admin_required
def zone_settings(zone_id):
    zone = db.session.get(ManagedZone, zone_id)
    if not zone:
        flash("Zone not found.", "error")
        return redirect(url_for("admin.dns"))
    if request.method == "POST":
        zone.registration_mode = request.form.get("registration_mode", "open")
        if zone.registration_mode not in {"open", "approval", "closed"}:
            zone.registration_mode = "open"
        try:
            zone.max_domains_per_user = int(request.form.get("max_domains_per_user", "")) or None
        except ValueError:
            zone.max_domains_per_user = None
        try:
            minimum_length = int(request.form.get("minimum_label_length", 1))
            maximum_length = int(request.form.get("maximum_label_length", 63))
        except (TypeError, ValueError):
            minimum_length, maximum_length = 1, 63
        zone.minimum_label_length = max(1, min(minimum_length, 63))
        zone.maximum_label_length = max(zone.minimum_label_length, min(maximum_length, 63))
        zone.reserved_labels = json.dumps(sorted({
            item.strip().lower() for item in request.form.get("reserved_labels", "").split(",") if item.strip()
        }))
        zone.allowed_record_types = json.dumps(request.form.getlist("allowed_record_types"))
        zone.allow_wildcard = request.form.get("allow_wildcard") == "on"
        zone.secondary_dns = json.dumps([
            item.strip() for item in request.form.get("secondary_dns", "").splitlines() if item.strip()
        ])
        audit("admin.zone.settings", zone.name)
        db.session.commit()
        flash("Zone policy saved.", "success")
    return render_template("management/zone_settings.html", zone=zone, json=json)


@bp.post("/dns/zones/<int:zone_id>/dnssec")
@admin_required
def update_zone_dnssec(zone_id):
    zone = db.session.get(ManagedZone, zone_id)
    if not zone:
        flash("Zone not found.", "error")
        return redirect(url_for("admin.dns"))
    try:
        adapter = make_provider(zone.provider.kind, decrypt_config(zone.provider.encrypted_config))
        if request.form.get("action") == "refresh":
            details = adapter.get_dnssec(zone.name, zone.remote_id)
            zone.dnssec_status = details.get("status", "unknown")
        else:
            enabled = request.form.get("action") == "enable"
            zone.dnssec_status = adapter.set_dnssec(zone.name, zone.remote_id, enabled)
            details = adapter.get_dnssec(zone.name, zone.remote_id)
        Setting.set(f"zone.{zone.id}.dnssec_details", json.dumps(details))
        audit("admin.zone.dnssec", f"{zone.name}:{zone.dnssec_status}")
        db.session.commit()
        flash("DNSSEC status updated.", "success")
    except (DNSProviderError, RuntimeError) as exc:
        db.session.rollback()
        flash(str(exc), "error")
    return redirect(url_for("admin.zone_settings", zone_id=zone.id))


@bp.post("/dns/zones/<int:zone_id>/secondary-check")
@admin_required
def check_zone_secondaries(zone_id):
    zone = db.session.get(ManagedZone, zone_id)
    if not zone:
        flash("Zone not found.", "error")
        return redirect(url_for("admin.dns"))
    results = check_secondaries(zone)
    zone.transfer_status = "healthy" if results and all(item["healthy"] for item in results) else (
        "not_configured" if not results else "failed"
    )
    Setting.set(f"zone.{zone.id}.secondary_results", json.dumps(results))
    audit("admin.zone.secondary_check", f"{zone.name}:{zone.transfer_status}")
    db.session.commit()
    if results:
        summary = ", ".join(
            f"{item['server']}: {'healthy' if item['healthy'] else item['error'] or 'failed'}" for item in results
        )
        flash(summary, "success" if zone.transfer_status == "healthy" else "error")
    else:
        flash("Configure at least one secondary DNS server first.", "info")
    return redirect(url_for("admin.zone_settings", zone_id=zone.id))


@bp.get("/domains/approvals")
@admin_required
def domain_approvals():
    return render_template(
        "management/approvals.html",
        domains=Domain.query.filter_by(status="pending").order_by(Domain.created_at).all(),
    )


@bp.get("/domains")
@admin_required
def domains():
    query_text = request.args.get("q", "").strip().lower()
    status = request.args.get("status", "").strip()
    query = Domain.query
    if query_text:
        query = query.filter(Domain.fqdn.ilike(f"%{query_text}%"))
    if status in {"active", "pending", "suspended"}:
        query = query.filter_by(status=status)
    page = max(1, request.args.get("page", 1, type=int))
    domains_page = query.order_by(Domain.created_at.desc()).paginate(page=page, per_page=50, error_out=False)
    return render_template(
        "management/domains.html", domains=domains_page, query=query_text, selected_status=status
    )


@bp.get("/domains.csv")
@admin_required
def export_domains():
    output = io.StringIO()
    writer = csv.writer(output)
    writer.writerow(["id", "domain", "status", "owner", "zone", "team", "records", "created_at"])
    for domain in Domain.query.order_by(Domain.id):
        writer.writerow([
            domain.id, domain.fqdn, domain.status, domain.owner.username, domain.zone.name,
            domain.team.slug if domain.team else "", len(domain.records), domain.created_at.isoformat(),
        ])
    return Response(
        output.getvalue(),
        mimetype="text/csv",
        headers={"Content-Disposition": "attachment; filename=domain-oss-domains.csv"},
    )


@bp.post("/domains/<int:domain_id>/status")
@admin_required
def update_domain_status(domain_id):
    domain = db.session.get(Domain, domain_id)
    status = request.form.get("status", "")
    if not domain or status not in {"active", "pending", "suspended"}:
        flash("Invalid domain status.", "error")
    else:
        domain.status = status
        audit("admin.domain.status", f"{domain.fqdn}: {status}")
        emit_event(
            "domain.status_changed",
            {"domain_id": domain.id, "name": domain.fqdn, "status": status},
            [domain.owner],
            "Domain status changed",
            f"{domain.fqdn} is now {status}.",
            "success" if status == "active" else "info",
        )
        db.session.commit()
        flash("Domain status updated.", "success")
    return redirect(request.referrer or url_for("admin.domains"))


@bp.get("/dns/jobs")
@admin_required
def dns_jobs():
    page = max(1, request.args.get("page", 1, type=int))
    jobs = DNSChangeJob.query.order_by(DNSChangeJob.created_at.desc()).paginate(page=page, per_page=50)
    return render_template("management/jobs.html", jobs=jobs)


@bp.post("/dns/jobs/<int:job_id>/retry")
@admin_required
def retry_job(job_id):
    job = db.session.get(DNSChangeJob, job_id)
    if not job:
        flash("DNS job not found.", "error")
    else:
        job.status = "pending"
        job.run_after = now_utc()
        db.session.commit()
        process_job(job)
        flash("DNS job processed.", "success")
    return redirect(url_for("admin.dns_jobs"))


@bp.route("/settings", methods=["GET", "POST"])
@admin_required
def settings():
    if request.method == "POST":
        site_name = request.form.get("site_name", "").strip()[:80]
        try:
            max_domains = max(1, min(int(request.form.get("max_domains_per_user", "3")), 100))
        except ValueError:
            max_domains = 3
        if not site_name:
            flash("Site name is required.", "error")
        else:
            Setting.set("site_name", site_name)
            Setting.set("max_domains_per_user", max_domains)
            Setting.set("registration_enabled", "1" if request.form.get("registration_enabled") else "0")
            audit("admin.settings.update", "site")
            db.session.commit()
            flash("Settings saved.", "success")
    return render_template("management/settings.html")


@bp.get("/audit")
@admin_required
def audit_log():
    entries = AuditLog.query.order_by(AuditLog.created_at.desc()).limit(250).all()
    return render_template("management/audit.html", entries=entries)


@bp.route("/webhooks", methods=["GET", "POST"])
@admin_required
def webhooks():
    if request.method == "POST":
        name = request.form.get("name", "").strip()[:80]
        url = request.form.get("url", "").strip()[:2048]
        events = ",".join(request.form.getlist("events")) or "*"
        if not name or not webhook_url_is_safe(url):
            flash("Enter a name and an HTTPS webhook URL.", "error")
        else:
            secret = request.form.get("secret", "").strip() or secrets.token_urlsafe(32)
            endpoint = WebhookEndpoint(
                name=name,
                url=url,
                events=events,
                encrypted_secret=encrypt_config({"secret": secret}),
            )
            db.session.add(endpoint)
            audit("admin.webhook.create", name)
            db.session.commit()
            flash(f"Webhook created. Save its signing secret now: {secret}", "success")
            return redirect(url_for("admin.webhooks"))
    return render_template(
        "management/webhooks.html",
        endpoints=WebhookEndpoint.query.order_by(WebhookEndpoint.created_at.desc()).all(),
    )


@bp.post("/webhooks/<int:endpoint_id>/test")
@admin_required
def test_webhook(endpoint_id):
    endpoint = db.session.get(WebhookEndpoint, endpoint_id)
    if not endpoint:
        flash("Webhook not found.", "error")
    else:
        deliver_webhook(endpoint, {
            "id": f"test-{secrets.token_hex(8)}",
            "type": "webhook.test",
            "created_at": now_utc().isoformat() + "Z",
            "data": {"endpoint_id": endpoint.id, "message": "Test delivery"},
        })
        db.session.commit()
        flash(
            "Webhook delivered successfully." if endpoint.last_status == "delivered" else
            f"Webhook test failed: {endpoint.last_error}",
            "success" if endpoint.last_status == "delivered" else "error",
        )
    return redirect(url_for("admin.webhooks"))


@bp.post("/webhooks/<int:endpoint_id>/toggle")
@admin_required
def toggle_webhook(endpoint_id):
    endpoint = db.session.get(WebhookEndpoint, endpoint_id)
    if endpoint:
        endpoint.enabled = not endpoint.enabled
        audit("admin.webhook.toggle", endpoint.name)
        db.session.commit()
    return redirect(url_for("admin.webhooks"))


@bp.post("/webhooks/<int:endpoint_id>/delete")
@admin_required
def delete_webhook(endpoint_id):
    endpoint = db.session.get(WebhookEndpoint, endpoint_id)
    if endpoint:
        audit("admin.webhook.delete", endpoint.name)
        db.session.delete(endpoint)
        db.session.commit()
    return redirect(url_for("admin.webhooks"))
