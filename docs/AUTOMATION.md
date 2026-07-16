# Automation and integrations

## REST API

Create a scoped key under **Account & security** and use `Authorization: Bearer dpo_...`. The OpenAPI document is served at `/api/v1/openapi.json`. See [API.md](API.md) for endpoints and examples.

## Terraform provider

The provider source is in `integrations/terraform-provider-domainoss`. Build it with:

```bash
cd integrations/terraform-provider-domainoss
go build
```

Configure the panel base URL and an API key with domain and DNS write scopes. The provider manages delegated domains and DNS records. Treat Terraform state as sensitive because it can contain record data and resource identifiers.

## ACME DNS-01

An API key with `acme:write` can create `_acme-challenge` TXT records without receiving general DNS write access. The create endpoint returns a one-time cleanup token. Delete the challenge after validation. Challenges expire after one hour and the worker removes expired records.

## Webhook signatures

Webhook requests contain JSON and an `X-Domain-OSS-Signature` header. Verify the HMAC SHA-256 digest over the exact request body with the endpoint secret before parsing or processing the event.

```python
import hashlib
import hmac

expected = "sha256=" + hmac.new(secret.encode(), request_body, hashlib.sha256).hexdigest()
if not hmac.compare_digest(expected, signature_header):
    raise ValueError("Invalid webhook signature")
```

Respond with a 2xx status promptly. Queue slow work in the receiving system.

## Prometheus metrics

Create an administrator API key with `admin:metrics` and scrape `/api/v1/metrics`. The endpoint reports instance object and DNS job counts. Do not expose the metrics endpoint without authentication.

## Email

SMTP enables email verification and password recovery. Set `PUBLIC_ORIGIN` so links use the external HTTPS address. When SMTP is unavailable, the application records a delivery warning and continues to operate; it does not expose recovery tokens in the web response.
