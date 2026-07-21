package org

import (
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

// clientFromProviderData extracts the shared *client.Client the provider
// stashes in ProviderData. It returns nil when ProviderData is unset —
// the framework calls Configure with nil before the provider is
// configured — and records a diagnostic on a type mismatch.
func clientFromProviderData(providerData any, diags *diag.Diagnostics) *client.Client {
	if providerData == nil {
		return nil
	}
	c, ok := providerData.(*client.Client)
	if !ok {
		diags.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("expected *client.Client, got %T", providerData),
		)

		return nil
	}

	return c
}
