//go:generate go run github.com/hashicorp/terraform-plugin-docs/cmd/tfplugindocs generate --provider-name splitsecure

// Package main is the entry point for the SplitSecure Terraform provider.
package main

import (
	"context"
	"log"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"

	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/provider"
)

var version = "dev"

func main() {
	err := providerserver.Serve(context.Background(), provider.New(version), providerserver.ServeOpts{
		Address: "registry.terraform.io/splitsecure/splitsecure",
	})
	if err != nil {
		log.Fatal(err)
	}
}
