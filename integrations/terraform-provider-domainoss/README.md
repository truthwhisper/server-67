# Terraform Provider for DigitalPlat Domain OSS

This provider manages domains and DNS records through the DigitalPlat Domain OSS REST API.

```hcl
terraform {
  required_providers {
    domainoss = {
      source = "digitalplatdev/domainoss"
    }
  }
}

provider "domainoss" {
  endpoint = "https://domains.example.org"
  api_key  = var.domain_oss_api_key
}

resource "domainoss_domain" "website" {
  label   = "website"
  zone_id = 1
}

resource "domainoss_dns_record" "website" {
  domain_id = domainoss_domain.website.id
  name      = "@"
  type      = "A"
  content   = "192.0.2.10"
  ttl       = 300
}
```

For local development, run `go build` and install the resulting binary through Terraform's development override mechanism. Set `DOMAIN_OSS_ENDPOINT` and `DOMAIN_OSS_API_KEY` instead of placing credentials in configuration files.
