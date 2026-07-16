package main

import (
	"log"

	"github.com/hashicorp/terraform-plugin-sdk/v2/plugin"
)

func main() {
	plugin.Serve(&plugin.ServeOpts{
		ProviderFunc: provider,
		ProviderAddr: "registry.terraform.io/digitalplatdev/domainoss",
		Debug:        false,
	})
	log.Print("Terraform provider stopped")
}
