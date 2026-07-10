package org

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"

	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

func TestClientFromProviderData(t *testing.T) {
	t.Parallel()

	// nil ProviderData (the framework's early Configure call) -> nil, no error.
	var d diag.Diagnostics
	if got := clientFromProviderData(nil, &d); got != nil || d.HasError() {
		t.Fatalf("nil provider data: got %v, diags %v", got, d)
	}

	// Wrong type -> nil and a diagnostic.
	d = diag.Diagnostics{}
	if got := clientFromProviderData("not a client", &d); got != nil || !d.HasError() {
		t.Fatalf("wrong type: got %v, diags %v", got, d)
	}

	// Correct type -> returned unchanged, no error.
	d = diag.Diagnostics{}
	c := &client.Client{OrgS2R: "s2r:test:org:x"}
	if got := clientFromProviderData(c, &d); got != c || d.HasError() {
		t.Fatalf("correct type: got %v, diags %v", got, d)
	}
}
