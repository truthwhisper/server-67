import requests

from .base import BaseProvider, DNSProviderError


class CloudflareProvider(BaseProvider):
    API_ROOT = "https://api.cloudflare.com/client/v4"

    def _request(self, method, path, **kwargs):
        try:
            response = requests.request(
                method,
                f"{self.API_ROOT}/{path.lstrip('/')}",
                headers={"Authorization": f"Bearer {self.config.get('api_token', '')}"},
                timeout=float(self.config.get("timeout", 8)),
                **kwargs,
            )
            data = response.json()
            if not response.ok or not data.get("success"):
                errors = data.get("errors") or [{"message": response.text[:200]}]
                raise DNSProviderError(f"Cloudflare API error: {errors[0].get('message', 'unknown error')}")
            return data
        except requests.RequestException as exc:
            raise DNSProviderError(f"Cloudflare API request failed: {exc}") from exc
        except ValueError as exc:
            raise DNSProviderError("Cloudflare returned an invalid response") from exc

    def test(self):
        self._request("GET", "/user/tokens/verify")
        return "Cloudflare API token is valid"

    def sync_rrset(self, zone, remote_id, name, record_type, values):
        if not remote_id:
            raise DNSProviderError("Cloudflare zone ID is required")
        existing = self._request(
            "GET", f"/zones/{remote_id}/dns_records", params={"type": record_type, "name": name}
        )["result"]
        for record in existing:
            self._request("DELETE", f"/zones/{remote_id}/dns_records/{record['id']}")
        for value in values:
            payload = {"type": record_type, "name": name, "content": value.content, "ttl": value.ttl}
            if value.priority is not None and record_type == "MX":
                payload["priority"] = value.priority
            elif value.priority is not None and record_type == "SRV":
                weight, port, target = value.content.split()
                payload.pop("content")
                payload["data"] = {
                    "priority": value.priority,
                    "weight": int(weight),
                    "port": int(port),
                    "target": target.rstrip("."),
                }
            self._request("POST", f"/zones/{remote_id}/dns_records", json=payload)

    def get_dnssec(self, zone, remote_id):
        if not remote_id:
            raise DNSProviderError("Cloudflare zone ID is required")
        result = self._request("GET", f"/zones/{remote_id}/dnssec")["result"]
        return {
            "status": result.get("status", "unknown"),
            "ds": result.get("ds", ""),
            "digest": result.get("digest", ""),
            "digest_algorithm": result.get("digest_algorithm", ""),
            "algorithm": result.get("algorithm", ""),
            "key_tag": result.get("key_tag", ""),
        }

    def set_dnssec(self, zone, remote_id, enabled):
        if not remote_id:
            raise DNSProviderError("Cloudflare zone ID is required")
        status = "active" if enabled else "disabled"
        result = self._request("PATCH", f"/zones/{remote_id}/dnssec", json={"status": status})["result"]
        return result.get("status", status)
