import ipaddress

from .models import DNSRecord
from .providers import RecordValue, make_provider
from .security import ALLOWED_RECORD_TYPES, RECORD_NAME_RE, decrypt_config


def absolute_record_name(domain, name):
    return domain.fqdn if name == "@" else f"{name}.{domain.fqdn}"


def validate_record(name, record_type, content, ttl, priority=None):
    name = name.strip().lower().rstrip(".") or "@"
    record_type = record_type.strip().upper()
    content = content.strip()
    if not RECORD_NAME_RE.fullmatch(name):
        return None, "Enter a valid record name."
    if record_type not in ALLOWED_RECORD_TYPES:
        return None, "Select a supported record type."
    try:
        ttl = int(ttl)
        if ttl < 60 or ttl > 86400:
            raise ValueError
    except (TypeError, ValueError):
        return None, "TTL must be between 60 and 86400 seconds."
    if not content or len(content) > 2048 or "\n" in content or "\r" in content:
        return None, "Enter a valid single-line record value."
    try:
        if record_type == "A":
            ipaddress.IPv4Address(content)
        elif record_type == "AAAA":
            ipaddress.IPv6Address(content)
        elif record_type in {"CNAME", "NS", "MX"}:
            if "." not in content.rstrip("."):
                raise ValueError
        if record_type == "SRV":
            parts = content.split()
            if len(parts) != 3 or not all(part.isdigit() for part in parts[:2]):
                raise ValueError
            weight, port = (int(part) for part in parts[:2])
            if weight > 65535 or port > 65535 or "." not in parts[2].rstrip("."):
                raise ValueError
        elif record_type == "CAA":
            parts = content.split(maxsplit=2)
            if len(parts) != 3 or not parts[0].isdigit() or int(parts[0]) > 255:
                raise ValueError
            if parts[1] not in {"issue", "issuewild", "iodef"}:
                raise ValueError
        if record_type in {"MX", "SRV"}:
            priority = int(priority)
            if priority < 0 or priority > 65535:
                raise ValueError
        else:
            priority = None
    except (TypeError, ValueError):
        return None, f"Enter a valid {record_type} record value."
    return {
        "name": name,
        "record_type": record_type,
        "content": content,
        "ttl": ttl,
        "priority": priority,
    }, None


def sync_rrset(domain, name, record_type, excluding_id=None, clear=False):
    query = DNSRecord.query.filter_by(domain_id=domain.id, name=name, record_type=record_type)
    if excluding_id is not None:
        query = query.filter(DNSRecord.id != excluding_id)
    records = [] if clear else query.order_by(DNSRecord.id).all()
    values = [RecordValue(item.content, item.ttl, item.priority) for item in records]
    provider_model = domain.zone.provider
    provider = make_provider(provider_model.kind, decrypt_config(provider_model.encrypted_config))
    provider.sync_rrset(
        domain.zone.name,
        domain.zone.remote_id,
        absolute_record_name(domain, name),
        record_type,
        values,
    )
