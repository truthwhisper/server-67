import json
from datetime import timedelta

from flask import has_request_context
from flask_login import current_user

from .extensions import db
from .models import ACMEChallenge, DNSChangeJob, DNSRecord, now_utc
from .notifications import emit_event
from .providers import DNSProviderError
from .services import sync_rrset


def enqueue_rrset(domain, name, record_type, *, clear=False, actor_id=None):
    if actor_id is None and has_request_context() and current_user.is_authenticated:
        actor_id = current_user.id
    job = DNSChangeJob(
        domain=domain,
        actor_id=actor_id,
        action="sync_rrset",
        payload=json.dumps({"name": name, "record_type": record_type, "clear": clear}),
    )
    db.session.add(job)
    db.session.flush()
    return job


def process_job(job):
    if job.status == "completed":
        return True
    job.status = "running"
    job.started_at = now_utc()
    job.attempts += 1
    db.session.flush()
    try:
        payload = json.loads(job.payload)
        if job.action != "sync_rrset" or not job.domain:
            raise RuntimeError("Unsupported or orphaned DNS job")
        sync_rrset(
            job.domain,
            payload["name"],
            payload["record_type"],
            clear=bool(payload.get("clear")),
        )
    except (DNSProviderError, RuntimeError, ValueError, KeyError) as exc:
        job.last_error = str(exc)[:2000]
        if job.attempts >= job.max_attempts:
            job.status = "failed"
            if job.domain:
                emit_event(
                    "dns.job_failed",
                    {"job_id": job.id, "domain": job.domain.fqdn, "error": job.last_error},
                    [job.domain.owner],
                    "DNS synchronization failed",
                    f"A DNS change for {job.domain.fqdn} could not be published: {job.last_error}",
                    "error",
                )
        else:
            job.status = "retrying"
            job.run_after = now_utc() + timedelta(seconds=min(3600, 15 * (2 ** (job.attempts - 1))))
        db.session.commit()
        return False
    job.status = "completed"
    job.last_error = None
    job.completed_at = now_utc()
    if job.attempts > 1 and job.domain:
        emit_event(
            "dns.job_recovered",
            {"job_id": job.id, "domain": job.domain.fqdn},
            [job.domain.owner],
            "DNS synchronization recovered",
            f"The queued DNS change for {job.domain.fqdn} was published successfully.",
            "success",
        )
    db.session.commit()
    return True


def process_pending_jobs(limit=50):
    cleanup_expired_acme()
    jobs = (
        DNSChangeJob.query.filter(
            DNSChangeJob.status.in_(["pending", "retrying"]),
            DNSChangeJob.run_after <= now_utc(),
        )
        .order_by(DNSChangeJob.created_at)
        .limit(limit)
        .all()
    )
    return sum(1 for job in jobs if process_job(job)), len(jobs)


def cleanup_expired_acme(limit=50):
    challenges = (
        ACMEChallenge.query.filter(
            ACMEChallenge.status.in_(["pending", "queued", "published"]),
            ACMEChallenge.expires_at <= now_utc(),
        )
        .order_by(ACMEChallenge.expires_at)
        .limit(limit)
        .all()
    )
    jobs = []
    for challenge in challenges:
        record = DNSRecord.query.filter_by(
            domain_id=challenge.domain_id,
            name=challenge.record_name,
            record_type="TXT",
            content=challenge.record_value,
        ).first()
        if record:
            db.session.delete(record)
        challenge.status = "expired"
        db.session.flush()
        jobs.append(enqueue_rrset(challenge.domain, challenge.record_name, "TXT"))
    if challenges:
        db.session.commit()
        for job in jobs:
            process_job(job)
    return len(challenges)
