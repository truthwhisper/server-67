# REST API

DigitalPlat Domain OSS exposes a JSON API under `/api/v1`. Discover the current surface at `/api/v1/openapi.json`.

## Authentication

Create a key in **Account & security** and send it as a bearer token:

```bash
curl -H "Authorization: Bearer $DOMAIN_OSS_API_KEY" \
  https://domains.example.org/api/v1/domains
```

Keys expire and can be revoked. Available scopes are:

- `domains:read` and `domains:write`
- `dns:read` and `dns:write`
- `acme:write`
- `admin:metrics`, available only to administrators

## Domains

```bash
curl -X POST -H "Authorization: Bearer $DOMAIN_OSS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"label":"website","zone_id":1}' \
  https://domains.example.org/api/v1/domains
```

List responses use `page` and `per_page` parameters and include pagination metadata. Domain creation follows the same zone naming, reservation, registration, and quota policies as the web interface.

## DNS records

```bash
curl -X POST -H "Authorization: Bearer $DOMAIN_OSS_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"name":"@","type":"A","content":"192.0.2.10","ttl":300}' \
  https://domains.example.org/api/v1/domains/1/records
```

DNS writes return synchronization job information. Failed provider requests are retried by `domain-oss worker`.

## ACME DNS-01

Publish a challenge with `POST /domains/{domain_id}/acme-challenges` and a JSON body containing `value` and optional `name`. Save the returned one-time `token`. Clean it up with `DELETE /domains/{domain_id}/acme-challenges/{token}`. A successful cleanup returns HTTP 204. Challenges expire after one hour and the worker removes their TXT records automatically.

## Errors and limits

Errors use `{"error":{"message":"...","status":400}}`. API keys are rate limited, request bodies are limited to 1 MiB, record values are bounded, and bulk record imports are limited to 500 records.
