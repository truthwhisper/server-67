package main

import (
	"context"
	"encoding/json"
	"net/http"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type domainData struct {
	ID     int    `json:"id"`
	Name   string `json:"name"`
	Label  string `json:"label"`
	Status string `json:"status"`
	Zone   string `json:"zone"`
}

func resourceDomain() *schema.Resource {
	return &schema.Resource{
		CreateContext: createDomain,
		ReadContext:   readDomain,
		DeleteContext: deleteDomain,
		Importer:      &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
		Schema: map[string]*schema.Schema{
			"label":   {Type: schema.TypeString, Required: true, ForceNew: true},
			"zone_id": {Type: schema.TypeInt, Required: true, ForceNew: true},
			"name":    {Type: schema.TypeString, Computed: true},
			"status":  {Type: schema.TypeString, Computed: true},
			"zone":    {Type: schema.TypeString, Computed: true},
		},
	}
}

func createDomain(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var response apiEnvelope
	err := meta.(*client).request(http.MethodPost, "/domains", map[string]interface{}{
		"label": data.Get("label"), "zone_id": data.Get("zone_id"),
	}, &response)
	if err != nil {
		return diag.FromErr(err)
	}
	var domain domainData
	if err := json.Unmarshal(response.Data, &domain); err != nil {
		return diag.FromErr(err)
	}
	data.SetId(strconv.Itoa(domain.ID))
	return readDomain(ctx, data, meta)
}

func readDomain(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var response apiEnvelope
	err := meta.(*client).request(http.MethodGet, "/domains/"+data.Id(), nil, &response)
	if err != nil {
		return diag.FromErr(err)
	}
	var domain domainData
	if err := json.Unmarshal(response.Data, &domain); err != nil {
		return diag.FromErr(err)
	}
	data.Set("label", domain.Label)
	data.Set("name", domain.Name)
	data.Set("status", domain.Status)
	data.Set("zone", domain.Zone)
	return nil
}

func deleteDomain(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	if err := meta.(*client).request(http.MethodDelete, "/domains/"+data.Id(), nil, nil); err != nil {
		return diag.FromErr(err)
	}
	data.SetId("")
	return nil
}
