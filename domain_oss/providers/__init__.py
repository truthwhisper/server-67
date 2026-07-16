from .base import DNSProviderError, RecordValue as RecordValue
from .bind import BindProvider
from .cloudflare import CloudflareProvider
from .powerdns import PowerDNSProvider


PROVIDERS = {
    "bind": BindProvider,
    "powerdns": PowerDNSProvider,
    "cloudflare": CloudflareProvider,
}


def make_provider(kind, config):
    try:
        return PROVIDERS[kind](config)
    except KeyError:
        raise DNSProviderError(f"Unsupported DNS provider: {kind}") from None


def config_from_form(kind, form):
    fields = {
        "bind": ("server", "port", "key_name", "key_secret", "algorithm"),
        "powerdns": ("api_url", "api_key"),
        "cloudflare": ("api_token",),
    }
    if kind not in fields:
        raise DNSProviderError("Select a supported DNS provider")
    config = {key: form.get(key, "").strip() for key in fields[kind]}
    required = {
        "bind": ("server", "key_name", "key_secret"),
        "powerdns": ("api_url", "api_key"),
        "cloudflare": ("api_token",),
    }
    missing = [key for key in required[kind] if not config.get(key)]
    if missing:
        raise DNSProviderError(f"Missing fields: {', '.join(missing)}")
    return config
