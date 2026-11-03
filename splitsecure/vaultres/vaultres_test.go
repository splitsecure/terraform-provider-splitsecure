package vaultres_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultres"
)

func validates(v validator.String, value string) bool {
	resp := &validator.StringResponse{}
	v.ValidateString(context.Background(), validator.StringRequest{ConfigValue: types.StringValue(value)}, resp)

	return !resp.Diagnostics.HasError()
}

func TestDurationValidator(t *testing.T) {
	t.Parallel()

	for value, want := range map[string]bool{"": true, "0": true, "30s": true, "1h30m": true, "-5s": false, "soon": false} {
		if got := validates(vaultres.DurationValidator(), value); got != want {
			t.Errorf("duration %q accepted = %v, want %v", value, got, want)
		}
	}
}

func TestRFC3339Validator(t *testing.T) {
	t.Parallel()

	for value, want := range map[string]bool{"2030-01-02T15:04:05Z": true, "2030-01-02": false, "tomorrow": false} {
		if got := validates(vaultres.RFC3339Validator(), value); got != want {
			t.Errorf("timestamp %q accepted = %v, want %v", value, got, want)
		}
	}
}

func TestSplitImportID(t *testing.T) {
	t.Parallel()

	vaultID, id, ok := vaultres.SplitImportID("vault-1/node-2")
	if !ok || vaultID != "vault-1" || id != "node-2" {
		t.Errorf("got %q, %q, %v", vaultID, id, ok)
	}

	for _, bad := range []string{"", "vault-1", "/node", "vault/"} {
		if _, _, ok := vaultres.SplitImportID(bad); ok {
			t.Errorf("%q should be rejected", bad)
		}
	}
}
