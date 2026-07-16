# DNS provider configuration

## BIND 9 with RFC 2136

DigitalPlat Domain OSS sends DNS UPDATE requests over TCP and authenticates them with TSIG. Create a dedicated key for the application and authorize only the required zone.

```text
key "domain-oss-key" {
    algorithm hmac-sha256;
    secret "REPLACE_WITH_BASE64_SECRET";
};

zone "example.org" {
    type primary;
    file "db.example.org";
    update-policy {
        grant domain-oss-key zonesub ANY;
    };
};
```

Enter the BIND server, port, key name, base64 secret, and algorithm. Restrict the update port to the application host. Prefer a more specific update policy when the delegated naming layout permits it. Never authorize unsigned updates by source address alone.

The provider test validates the TSIG configuration and TCP connection. Publish a temporary record and query the authoritative server to verify the complete path.

## PowerDNS Authoritative Server

Enable the HTTP API with a dedicated API key and a network ACL that allows only the application host. Example PowerDNS settings:

```text
api=yes
api-key=REPLACE_WITH_LONG_RANDOM_KEY
webserver=yes
webserver-address=127.0.0.1
webserver-port=8081
webserver-allow-from=127.0.0.1
```

Use a reverse proxy or private network when the API is on another host. Enter the API origin without `/api/v1`, such as `https://pdns-api.example.org`. The default remote zone identifier is the FQDN with a trailing dot.

PowerDNS zones must already exist. The panel replaces or deletes individual RRsets through the Authoritative Server API.

## Cloudflare

Create an API token restricted to the required account and zones. DNS publishing requires `Zone:DNS:Edit` and zone discovery normally requires `Zone:Zone:Read`. DNSSEC operations require the relevant DNSSEC permission granted by Cloudflare.

Enter the API token and use the Cloudflare zone ID as the managed zone's remote ID. Do not use the global API key.

The adapter lists matching records, removes the existing RRset, and creates the requested values. DNSSEC status and enable or disable actions are available for Cloudflare zones.

## Provider health and errors

The provider page records the latest connectivity result and error. A successful connection test does not prove that a particular zone can be updated, so always publish and resolve a temporary record after configuration changes.

Provider failures are saved on DNS jobs and retried by the worker. Repeated authentication errors should be fixed before retrying the queue.
