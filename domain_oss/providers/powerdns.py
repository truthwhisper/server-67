import requests

from .base import BaseProvider, DNSProviderError, canonical_content


class PowerDNSProvider(BaseProvider):
    def _request(self, method, path, **kwargs):
        base_url = self.config.get("api_url", "").rstrip("/")
        if not base_url.startswith(("http://", "https://")):
            raise DNSProviderError("PowerDNS API URL must use HTTP or HTTPS")
        try:
            response = requests.request(
                method,
                f"{base_url}/{path.lstrip('/')}",
                headers={"X-API-Key": self.config.get("api_key", "")},
                timeout=float(self.config.get("timeout", 8)),
                **kwargs,
            )
            response.raise_for_status()
            return response
        except requests.RequestException as exc:
            detail = exc.response.text[:300] if exc.response is not None else str(exc)
            raise DNSProviderError(f"PowerDNS API request failed: {detail}") from exc

    def test(self):
        self._request("GET", "/api/v1/servers/localhost")
        return "PowerDNS API connection succeeded"

    def sync_rrset(self, zone, remote_id, name, record_type, values):
        zone_id = remote_id or f"{zone}."
        payload = {
            "rrsets": [{
                "name": f"{name.rstrip('.')}.",
                "type": record_type,
                "ttl": values[0].ttl if values else 300,
                "changetype": "REPLACE" if values else "DELETE",
                "records": [
                    {"content": canonical_content(record_type, item), "disabled": False} for item in values
                ],
            }]
        }
        self._request("PATCH", f"/api/v1/servers/localhost/zones/{zone_id}", json=payload)

