package vaultres_test

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi/vaultfake"
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

func folderConfig(ctx context.Context, t *testing.T, folder types.List, folderID types.String) tfsdk.Config {
	t.Helper()

	s := rschema.Schema{Attributes: vaultres.CommonAttributes("record")}
	objType, ok := s.Type().TerraformType(ctx).(tftypes.Object)

	if !ok {
		t.Fatal("schema type is not an object")
	}

	values := make(map[string]tftypes.Value, len(objType.AttributeTypes))
	for name, typ := range objType.AttributeTypes {
		values[name] = tftypes.NewValue(typ, nil)
	}

	cfg := tfsdk.Config{Schema: s, Raw: tftypes.NewValue(objType, values)}

	state := tfsdk.State{Schema: s, Raw: cfg.Raw}
	if diags := state.SetAttribute(ctx, path.Root("folder"), folder); diags.HasError() {
		t.Fatalf("setting folder: %v", diags)
	}

	if diags := state.SetAttribute(ctx, path.Root("folder_id"), folderID); diags.HasError() {
		t.Fatalf("setting folder_id: %v", diags)
	}

	return tfsdk.Config{Schema: s, Raw: state.Raw}
}

func TestCommonAttributes_RefuseFolderAndFolderIDTogether(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	attrs := vaultres.CommonAttributes("record")

	folderID, ok := attrs["folder_id"].(rschema.StringAttribute)
	if !ok {
		t.Fatal("folder_id is not a string attribute")
	}

	path1, _ := types.ListValue(types.StringType, []attr.Value{types.StringValue("terraform")})

	for name, tc := range map[string]struct {
		folder  types.List
		id      types.String
		wantErr bool
	}{
		"folder only":    {path1, types.StringNull(), false},
		"folder_id only": {types.ListNull(types.StringType), types.StringValue("f1"), false},
		"both":           {path1, types.StringValue("f1"), true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var diags diag.Diagnostics

			for _, v := range folderID.Validators {
				resp := &validator.StringResponse{}
				v.ValidateString(ctx, validator.StringRequest{
					Path:           path.Root("folder_id"),
					PathExpression: path.MatchRoot("folder_id"),
					Config:         folderConfig(ctx, t, tc.folder, tc.id),
					ConfigValue:    tc.id,
				}, resp)
				diags.Append(resp.Diagnostics...)
			}

			if diags.HasError() != tc.wantErr {
				t.Errorf("errors = %v, want error %v", diags, tc.wantErr)
			}
		})
	}
}

func TestParentNode_UsesFolderIDWithoutCreatingFolders(t *testing.T) {
	t.Parallel()

	// An empty fake serves no folder RPCs, so any lookup would error.
	c := vaultfake.New(t, vaultfake.Handlers{})

	var diags diag.Diagnostics

	got, ok := vaultres.ParentNode(context.Background(), c.VaultBrowse, "vault-1", types.ListNull(types.StringType), types.StringValue("f1"), &diags)
	if !ok || got != "f1" || diags.HasError() {
		t.Fatalf("got %q, ok %v, diags %v", got, ok, diags)
	}

	got, ok = vaultres.ParentNode(context.Background(), c.VaultBrowse, "vault-1", types.ListNull(types.StringType), types.StringNull(), &diags)
	if !ok || got != "" {
		t.Fatalf("unset folder: got %q, ok %v", got, ok)
	}
}
