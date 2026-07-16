from abc import ABC, abstractmethod
from dataclasses import dataclass


@dataclass
class RecordValue:
    content: str
    ttl: int = 300
    priority: int | None = None


class DNSProviderError(RuntimeError):
    pass


class BaseProvider(ABC):
    def __init__(self, config):
        self.config = config

    @abstractmethod
    def test(self):
        raise NotImplementedError

    @abstractmethod
    def sync_rrset(self, zone, remote_id, name, record_type, values):
        raise NotImplementedError

    def get_dnssec(self, zone, remote_id):
        raise DNSProviderError("DNSSEC management is not supported by this provider adapter")

    def set_dnssec(self, zone, remote_id, enabled):
        raise DNSProviderError("DNSSEC management is not supported by this provider adapter")


def canonical_content(record_type, value):
    content = value.content.strip()
    if record_type == "MX":
        return f"{value.priority or 0} {content.rstrip('.')}."
    if record_type == "SRV" and value.priority is not None:
        parts = content.split()
        if len(parts) == 3:
            parts[-1] = f"{parts[-1].rstrip('.')}."
            content = " ".join(parts)
        return f"{value.priority} {content}"
    if record_type in {"CNAME", "NS"}:
        return f"{content.rstrip('.')}."
    if record_type == "TXT" and not (content.startswith('"') and content.endswith('"')):
        escaped = content.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return content
