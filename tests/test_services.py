import pytest

from domain_oss.providers.base import RecordValue, canonical_content
from domain_oss.providers.cloudflare import CloudflareProvider
from domain_oss.dns_tools import parse_nameserver
from domain_oss.services import validate_record


@pytest.mark.parametrize(("record_type", "content"), [
    ("A", "192.0.2.4"),
    ("AAAA", "2001:db8::4"),
    ("CNAME", "target.example.org"),
    ("TXT", "domain verification token"),
])
def test_valid_records(record_type, content):
    value, error = validate_record("@", record_type, content, "300")
    assert error is None
    assert value["record_type"] == record_type


def test_invalid_ipv4_record():
    value, error = validate_record("@", "A", "999.2.3.4", "300")
    assert value is None
    assert "valid A" in error


def test_ttl_is_bounded():
    assert validate_record("@", "TXT", "hello", "59")[0] is None
    assert validate_record("@", "TXT", "hello", "86401")[0] is None


def test_mx_content_for_rfc2136_and_powerdns():
    value = RecordValue("mail.example.org.", 300, 10)
    assert canonical_content("MX", value) == "10 mail.example.org."


def test_srv_content_for_rfc2136_and_powerdns():
    value = RecordValue("5 5060 sip.example.org", 300, 10)
    assert canonical_content("SRV", value) == "10 5 5060 sip.example.org."
    parsed, error = validate_record("_sip._tcp", "SRV", value.content, "300", "10")
    assert error is None
    assert parsed["priority"] == 10


@pytest.mark.parametrize("content", ["5060 target.example.org", "x 5060 target.example.org"])
def test_invalid_srv_content_is_rejected(content):
    value, error = validate_record("_sip._tcp", "SRV", content, "300", "10")
    assert value is None
    assert "valid SRV" in error


def test_provider_content_is_dns_canonical():
    assert canonical_content("CNAME", RecordValue("target.example.org")) == "target.example.org."
    assert canonical_content("TXT", RecordValue('hello "world"')) == '"hello \\"world\\""'


def test_secondary_nameserver_port_parsing():
    assert parse_nameserver("127.0.0.1:15353") == ("127.0.0.1", 15353)
    assert parse_nameserver("[::1]:5353") == ("::1", 5353)


def test_cloudflare_srv_uses_structured_record_data(monkeypatch):
    provider = CloudflareProvider({"api_token": "test"})
    calls = []

    def request(method, path, **kwargs):
        calls.append((method, path, kwargs))
        return {"result": []} if method == "GET" else {"result": {}}

    monkeypatch.setattr(provider, "_request", request)
    provider.sync_rrset(
        "example.org",
        "zone-id",
        "_sip._tcp.example.org",
        "SRV",
        [RecordValue("5 5060 sip.example.org", 300, 10)],
    )
    payload = calls[-1][2]["json"]
    assert payload["data"] == {
        "priority": 10,
        "weight": 5,
        "port": 5060,
        "target": "sip.example.org",
    }
    assert "content" not in payload


def test_cloudflare_dnssec_contract(monkeypatch):
    provider = CloudflareProvider({"api_token": "test"})

    def request(method, path, **kwargs):
        if method == "GET":
            return {"result": {"status": "active", "ds": "12345 13 2 abc"}}
        assert kwargs["json"] == {"status": "active"}
        return {"result": {"status": "active"}}

    monkeypatch.setattr(provider, "_request", request)
    assert provider.set_dnssec("example.org", "zone-id", True) == "active"
    assert provider.get_dnssec("example.org", "zone-id")["ds"] == "12345 13 2 abc"
