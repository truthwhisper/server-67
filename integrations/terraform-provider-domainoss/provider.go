package main

import (
	"context"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/validation"
)

func provider() *schema.Provider {
	return &schema.Provider{
		Schema: map[string]*schema.Schema{
			"endpoint": {
				Type:         schema.TypeString,
				Optional:     true,
				DefaultFunc:  schema.EnvDefaultFunc("DOMAIN_OSS_ENDPOINT", nil),
				ValidateFunc: validation.IsURLWithHTTPorHTTPS,
			},
			"api_key": {
				Type:        schema.TypeString,
				Optional:    true,
				Sensitive:   true,
				DefaultFunc: schema.EnvDefaultFunc("DOMAIN_OSS_API_KEY", nil),
			},
		},
		ResourcesMap: map[string]*schema.Resource{
			"domainoss_domain":     resourceDomain(),
			"domainoss_dns_record": resourceDNSRecord(),
		},
		ConfigureContextFunc: configureProvider,
	}
}

func configureProvider(ctx context.Context, data *schema.ResourceData) (interface{}, diag.Diagnostics) {
	return newClient(data.Get("endpoint").(string), data.Get("api_key").(string)), nil
}
