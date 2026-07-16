import socket

import dns.query
import dns.rcode
import dns.tsigkeyring
import dns.update

from .base import BaseProvider, DNSProviderError, canonical_content


class BindProvider(BaseProvider):
    def _keyring(self):
        try:
            return dns.tsigkeyring.from_text({self.config["key_name"]: self.config["key_secret"]})
        except (KeyError, ValueError) as exc:
            raise DNSProviderError(f"Invalid TSIG configuration: {exc}") from exc

    def test(self):
        server = self.config.get("server")
        if not server:
            raise DNSProviderError("BIND server is required")
        self._keyring()
        try:
            with socket.create_connection((server, int(self.config.get("port", 53))), timeout=5):
                pass
        except OSError as exc:
            raise DNSProviderError(f"Could not connect to the BIND update service: {exc}") from exc
        return f"RFC 2136 updates configured for {server}"

    def sync_rrset(self, zone, remote_id, name, record_type, values):
        try:
            algorithm = self.config.get("algorithm", "hmac-sha256")
            update = dns.update.Update(zone, keyring=self._keyring(), keyalgorithm=algorithm)
            relative_name = name.removesuffix("." + zone).removesuffix(".") or "@"
            update.delete(relative_name, record_type)
            for value in values:
                update.add(relative_name, value.ttl, record_type, canonical_content(record_type, value))
            response = dns.query.tcp(
                update,
                self.config["server"],
                port=int(self.config.get("port", 53)),
                timeout=float(self.config.get("timeout", 5)),
            )
        except DNSProviderError:
            raise
        except Exception as exc:
            raise DNSProviderError(f"BIND update failed: {exc}") from exc
        if response.rcode() != dns.rcode.NOERROR:
            raise DNSProviderError(f"BIND rejected the update: {dns.rcode.to_text(response.rcode())}")
