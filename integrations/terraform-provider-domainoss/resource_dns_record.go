package main

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"

	"github.com/hashicorp/terraform-plugin-sdk/v2/diag"
	"github.com/hashicorp/terraform-plugin-sdk/v2/helper/schema"
)

type recordData struct {
	ID       int    `json:"id"`
	Name     string `json:"name"`
	Type     string `json:"type"`
	Content  string `json:"content"`
	TTL      int    `json:"ttl"`
	Priority *int   `json:"priority"`
}

func resourceDNSRecord() *schema.Resource {
	return &schema.Resource{
		CreateContext: createDNSRecord,
		ReadContext:   readDNSRecord,
		UpdateContext: updateDNSRecord,
		DeleteContext: deleteDNSRecord,
		Importer:      &schema.ResourceImporter{StateContext: schema.ImportStatePassthroughContext},
		Schema: map[string]*schema.Schema{
			"domain_id": {Type: schema.TypeInt, Required: true, ForceNew: true},
			"name":      {Type: schema.TypeString, Required: true},
			"type":      {Type: schema.TypeString, Required: true},
			"content":   {Type: schema.TypeString, Required: true},
			"ttl":       {Type: schema.TypeInt, Optional: true, Default: 300},
			"priority":  {Type: schema.TypeInt, Optional: true},
		},
	}
}

func recordPath(data *schema.ResourceData) string {
	return fmt.Sprintf("/domains/%d/records", data.Get("domain_id").(int))
}

func recordPayload(data *schema.ResourceData) map[string]interface{} {
	payload := map[string]interface{}{
		"name": data.Get("name"), "type": data.Get("type"), "content": data.Get("content"), "ttl": data.Get("ttl"),
	}
	if value, ok := data.GetOk("priority"); ok {
		payload["priority"] = value
	}
	return payload
}

func createDNSRecord(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var response apiEnvelope
	if err := meta.(*client).request(http.MethodPost, recordPath(data), recordPayload(data), &response); err != nil {
		return diag.FromErr(err)
	}
	var record recordData
	if err := json.Unmarshal(response.Data, &record); err != nil {
		return diag.FromErr(err)
	}
	data.SetId(strconv.Itoa(record.ID))
	return readDNSRecord(ctx, data, meta)
}

func readDNSRecord(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	var response struct {
		Data []recordData `json:"data"`
	}
	if err := meta.(*client).request(http.MethodGet, recordPath(data), nil, &response); err != nil {
		return diag.FromErr(err)
	}
	for _, record := range response.Data {
		if strconv.Itoa(record.ID) == data.Id() {
			data.Set("name", record.Name)
			data.Set("type", record.Type)
			data.Set("content", record.Content)
			data.Set("ttl", record.TTL)
			if record.Priority != nil {
				data.Set("priority", *record.Priority)
			}
			return nil
		}
	}
	data.SetId("")
	return nil
}

func updateDNSRecord(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	path := recordPath(data) + "/" + data.Id()
	if err := meta.(*client).request(http.MethodPatch, path, recordPayload(data), nil); err != nil {
		return diag.FromErr(err)
	}
	return readDNSRecord(ctx, data, meta)
}

func deleteDNSRecord(ctx context.Context, data *schema.ResourceData, meta interface{}) diag.Diagnostics {
	path := recordPath(data) + "/" + data.Id()
	if err := meta.(*client).request(http.MethodDelete, path, nil, nil); err != nil {
		return diag.FromErr(err)
	}
	data.SetId("")
	return nil
}
