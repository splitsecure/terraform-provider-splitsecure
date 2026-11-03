package vault

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	dschema "github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	vaultcatalogv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultcatalog/v1"
	vaulttypesv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaulttypes/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi/vaultfake"
)

func TestVaultSchema_Attributes(t *testing.T) {
	t.Parallel()

	resp := &datasource.SchemaResponse{}
	NewVaultDataSource().Schema(context.Background(), datasource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}

	if !resp.Schema.Attributes["name"].IsOptional() || !resp.Schema.Attributes["id"].IsOptional() {
		t.Error("name and id should be Optional")
	}

	if !resp.Schema.Attributes["org_s2r"].IsOptional() {
		t.Error("org_s2r should be Optional")
	}

	for _, name := range []string{"id", "custody_class", "status", "team_ids"} {
		attr, ok := resp.Schema.Attributes[name]
		if !ok || !attr.IsComputed() {
			t.Errorf("attribute %q should be Computed", name)
		}
	}
}

func catalogWith(pages ...*vaultcatalogv1.ListVaultsResponse) *vaultfake.Catalog {
	calls := 0

	return &vaultfake.Catalog{
		OnListSharedWithMe: func(*vaultcatalogv1.ListSharedWithMeRequest) (*vaultcatalogv1.ListSharedWithMeResponse, error) {
			return &vaultcatalogv1.ListSharedWithMeResponse{}, nil
		},
		OnListVaults: func(*vaultcatalogv1.ListVaultsRequest) (*vaultcatalogv1.ListVaultsResponse, error) {
			page := pages[calls]
			calls++

			return page, nil
		},
	}
}

func TestFindByLabel_PagesUntilMatch(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Catalog: catalogWith(
		&vaultcatalogv1.ListVaultsResponse{
			Vaults:     []*vaultcatalogv1.VaultSummary{{VaultId: "v1", Label: "other"}},
			NextCursor: []byte("next"),
		},
		&vaultcatalogv1.ListVaultsResponse{
			Vaults: []*vaultcatalogv1.VaultSummary{{VaultId: "v2", Label: "prod"}},
		},
	)})

	got, err := (&vaultDataSource{client: c}).findByName(context.Background(), "s2r:test:org:acme", "prod")
	if err != nil {
		t.Fatalf("findByName: %v", err)
	}

	if got.VaultID != "v2" || got.Summary == nil {
		t.Errorf("match = %+v, want vault v2", got)
	}
}

func TestFindByLabel_ErrorsOnNoMatch(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Catalog: catalogWith(
		&vaultcatalogv1.ListVaultsResponse{Vaults: []*vaultcatalogv1.VaultSummary{{VaultId: "v1", Label: "other"}}},
	)})

	_, err := (&vaultDataSource{client: c}).findByName(context.Background(), "s2r:test:org:acme", "prod")
	if !errors.Is(err, errVaultNotFound) {
		t.Fatalf("err = %v, want errVaultNotFound", err)
	}
}

func TestFindByLabel_ErrorsOnAmbiguousMatch(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Catalog: catalogWith(
		&vaultcatalogv1.ListVaultsResponse{
			Vaults:     []*vaultcatalogv1.VaultSummary{{VaultId: "v1", Label: "prod"}},
			NextCursor: []byte("next"),
		},
		&vaultcatalogv1.ListVaultsResponse{Vaults: []*vaultcatalogv1.VaultSummary{{VaultId: "v2", Label: "prod"}}},
	)})

	_, err := (&vaultDataSource{client: c}).findByName(context.Background(), "s2r:test:org:acme", "prod")
	if !errors.Is(err, errVaultAmbig) {
		t.Fatalf("err = %v, want errVaultAmbig", err)
	}
}

func sharedFolder(vaultID, nodeID, label string) *vaultcatalogv1.SharedNode {
	return &vaultcatalogv1.SharedNode{
		VaultId:    vaultID,
		VaultLabel: "prod",
		Node:       &vaulttypesv1.Node{NodeId: nodeID, Label: label, IsDir: true},
	}
}

func catalogWithShared(vaults []*vaultcatalogv1.VaultSummary, shared ...*vaultcatalogv1.SharedNode) *vaultfake.Catalog {
	return &vaultfake.Catalog{
		OnListVaults: func(*vaultcatalogv1.ListVaultsRequest) (*vaultcatalogv1.ListVaultsResponse, error) {
			return &vaultcatalogv1.ListVaultsResponse{Vaults: vaults}, nil
		},
		OnListSharedWithMe: func(*vaultcatalogv1.ListSharedWithMeRequest) (*vaultcatalogv1.ListSharedWithMeResponse, error) {
			return &vaultcatalogv1.ListSharedWithMeResponse{SharedNodes: shared}, nil
		},
	}
}

func TestFindByLabel_FallsBackToSharedNodes(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Catalog: catalogWithShared(
		[]*vaultcatalogv1.VaultSummary{{VaultId: "v1", Label: "other"}},
		sharedFolder("v2", "n1", "terraform"),
		sharedFolder("v2", "n2", "ci"),
	)})

	got, err := (&vaultDataSource{client: c}).findByName(context.Background(), "s2r:test:org:acme", "prod")
	if err != nil {
		t.Fatalf("findByName: %v", err)
	}

	if got.VaultID != "v2" || got.Summary != nil {
		t.Errorf("match = %+v", got)
	}
}

func TestFindByLabel_DedupesVaultInBothLists(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Catalog: catalogWithShared(
		[]*vaultcatalogv1.VaultSummary{{VaultId: "v1", Label: "prod"}},
		sharedFolder("v1", "n1", "terraform"),
	)})

	got, err := (&vaultDataSource{client: c}).findByName(context.Background(), "s2r:test:org:acme", "prod")
	if err != nil {
		t.Fatalf("findByName: %v", err)
	}

	if got.Summary == nil {
		t.Errorf("match = %+v", got)
	}
}

func TestFindByLabel_ErrorsOnSameLabelAcrossLists(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Catalog: catalogWithShared(
		[]*vaultcatalogv1.VaultSummary{{VaultId: "v1", Label: "prod"}},
		sharedFolder("v2", "n1", "terraform"),
	)})

	_, err := (&vaultDataSource{client: c}).findByName(context.Background(), "s2r:test:org:acme", "prod")
	if !errors.Is(err, errVaultAmbig) {
		t.Fatalf("err = %v, want errVaultAmbig", err)
	}
}

func TestLookup_ByIDDescribesVault(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnDescribeVault: func(req *vaultbrowsev1.DescribeVaultRequest) (*vaultbrowsev1.DescribeVaultResponse, error) {
			if req.GetBase().GetVaultId() != "v7" {
				t.Errorf("vault id = %q", req.GetBase().GetVaultId())
			}

			return &vaultbrowsev1.DescribeVaultResponse{
				VaultId:      "v7",
				Label:        "prod",
				CustodyClass: vaulttypesv1.CustodyClass_CUSTODY_CLASS_ONLINE,
				Status:       vaulttypesv1.VaultStatus_VAULT_STATUS_ACTIVE,
			}, nil
		},
	}})

	config := &vaultDataSourceModel{ID: types.StringValue("v7"), Name: types.StringUnknown()}

	got, err := (&vaultDataSource{client: c}).lookup(context.Background(), "s2r:test:org:acme", config)
	if err != nil {
		t.Fatalf("lookup: %v", err)
	}

	if got.VaultID != "v7" || got.Name != "prod" || got.Described == nil || got.Summary != nil {
		t.Errorf("match = %+v", got)
	}

	if enumName(got.Described.GetCustodyClass().String(), "CUSTODY_CLASS_") != "online" {
		t.Errorf("custody class = %v", got.Described.GetCustodyClass())
	}
}

func TestLookup_ByIDErrorsWhenVaultIsUnknown(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnDescribeVault: func(*vaultbrowsev1.DescribeVaultRequest) (*vaultbrowsev1.DescribeVaultResponse, error) {
			return nil, connect.NewError(connect.CodeNotFound, errVaultNotFound)
		},
	}})

	_, err := (&vaultDataSource{client: c}).lookup(context.Background(), "s2r:test:org:acme", &vaultDataSourceModel{ID: types.StringValue("v7")})
	if err == nil {
		t.Fatal("expected an error")
	}
}

func TestLookup_ByNameWhenIDUnset(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Catalog: catalogWithShared([]*vaultcatalogv1.VaultSummary{{VaultId: "v1", Label: "prod"}})})

	got, err := (&vaultDataSource{client: c}).lookup(context.Background(), "s2r:test:org:acme", &vaultDataSourceModel{Name: types.StringValue("prod"), ID: types.StringNull()})
	if err != nil || got.VaultID != "v1" || got.Name != "prod" {
		t.Fatalf("got %+v, err %v", got, err)
	}
}

func TestVaultSchema_RefusesBothOrNeitherOfNameAndID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	resp := &datasource.SchemaResponse{}
	NewVaultDataSource().Schema(ctx, datasource.SchemaRequest{}, resp)

	nameAttr, ok := resp.Schema.Attributes["name"].(dschema.StringAttribute)
	if !ok {
		t.Fatal("name is not a string attribute")
	}

	for name, tc := range map[string]struct {
		name, id types.String
		wantErr  bool
	}{
		"name only": {types.StringValue("prod"), types.StringNull(), false},
		"id only":   {types.StringNull(), types.StringValue("v1"), false},
		"both":      {types.StringValue("prod"), types.StringValue("v1"), true},
		"neither":   {types.StringNull(), types.StringNull(), true},
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			raw := tftypes.NewValue(resp.Schema.Type().TerraformType(ctx), nil)
			state := tfsdk.State{Schema: resp.Schema, Raw: raw}

			model := vaultDataSourceModel{
				ID: tc.id, Name: tc.name, OrgS2R: types.StringNull(), CustodyClass: types.StringNull(), Status: types.StringNull(),
				TeamIDs: types.ListNull(types.StringType),
			}
			if diags := state.Set(ctx, &model); diags.HasError() {
				t.Fatalf("building config: %v", diags)
			}

			var diags diag.Diagnostics

			for _, v := range nameAttr.Validators {
				vr := &validator.StringResponse{}
				v.ValidateString(ctx, validator.StringRequest{
					Path:           path.Root("name"),
					PathExpression: path.MatchRoot("name"),
					Config:         tfsdk.Config{Schema: resp.Schema, Raw: state.Raw},
					ConfigValue:    tc.name,
				}, vr)
				diags.Append(vr.Diagnostics...)
			}

			if diags.HasError() != tc.wantErr {
				t.Errorf("errors = %v, want error %v", diags, tc.wantErr)
			}
		})
	}
}
