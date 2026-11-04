package vault

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	authzv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/authz/v1"
	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi/vaultfake"
)

const (
	testGrantee = "s2r:us:user:abc"
	otherGrant  = "s2r:us:group:org/grp"
)

func grantSchema(ctx context.Context, t *testing.T) resource.SchemaResponse {
	t.Helper()

	resp := resource.SchemaResponse{}
	NewGrantResource().Schema(ctx, resource.SchemaRequest{}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}

	return resp
}

func grantState(ctx context.Context, t *testing.T, m *grantModel) tfsdk.State {
	t.Helper()

	s := grantSchema(ctx, t).Schema
	state := tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}

	if diags := state.Set(ctx, m); diags.HasError() {
		t.Fatalf("building state: %v", diags)
	}

	return state
}

func grantModelOf(tier string) *grantModel {
	return &grantModel{
		ID:      types.StringUnknown(),
		VaultID: types.StringValue("vault-1"),
		NodeID:  types.StringValue("node-1"),
		Grantee: types.StringValue(testGrantee),
		Tier:    types.StringValue(tier),
		IDPID:   types.StringNull(),
	}
}

func TestGrantSchema_Attributes(t *testing.T) {
	t.Parallel()

	s := grantSchema(context.Background(), t).Schema

	for _, name := range []string{"vault_id", "node_id", "grantee", "tier"} {
		if !s.Attributes[name].IsRequired() {
			t.Errorf("%q should be Required", name)
		}
	}

	if !s.Attributes["idp_id"].IsOptional() {
		t.Error("idp_id should be Optional")
	}
}

func TestGrantCreate_PutsOneGrantee(t *testing.T) {
	t.Parallel()

	var got *vaultbrowsev1.PutGrantsRequest

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnPutGrants: func(req *vaultbrowsev1.PutGrantsRequest) (*vaultbrowsev1.PutGrantsResponse, error) {
			got = req

			return &vaultbrowsev1.PutGrantsResponse{}, nil
		},
	}})

	ctx := context.Background()
	plan := grantState(ctx, t, grantModelOf("use"))
	resp := &resource.CreateResponse{State: grantState(ctx, t, grantModelOf("use"))}

	(&grantResource{client: c}).Create(ctx, resource.CreateRequest{Plan: tfsdk.Plan{Schema: plan.Schema, Raw: plan.Raw}}, resp)

	base := got.GetBase()
	if resp.Diagnostics.HasError() || base.GetVaultId() != "vault-1" || base.GetNodeId() != "node-1" || base.GetTier() != authzv1.Tier_TIER_USE ||
		len(base.GetGranteeIds()) != 1 || base.GetGranteeIds()[0] != testGrantee || base.GetIdpId() != "" {
		t.Fatalf("request = %v, diags = %v", got, resp.Diagnostics)
	}

	var state grantModel

	resp.State.Get(ctx, &state)

	if state.ID.ValueString() != "vault-1/node-1/"+testGrantee {
		t.Errorf("id = %q", state.ID.ValueString())
	}
}

func TestGrantUpdate_ChangesTierInPlace(t *testing.T) {
	t.Parallel()

	var got *vaultbrowsev1.PutGrantsRequest

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnPutGrants: func(req *vaultbrowsev1.PutGrantsRequest) (*vaultbrowsev1.PutGrantsResponse, error) {
			got = req

			return &vaultbrowsev1.PutGrantsResponse{}, nil
		},
	}})

	ctx := context.Background()
	plan := grantState(ctx, t, grantModelOf("edit"))
	resp := &resource.UpdateResponse{State: grantState(ctx, t, grantModelOf("use"))}

	(&grantResource{client: c}).Update(ctx, resource.UpdateRequest{Plan: tfsdk.Plan{Schema: plan.Schema, Raw: plan.Raw}}, resp)

	if resp.Diagnostics.HasError() || got.GetBase().GetTier() != authzv1.Tier_TIER_EDIT {
		t.Fatalf("request = %v, diags = %v", got, resp.Diagnostics)
	}
}

func readGrant(ctx context.Context, t *testing.T, c *grantResource, tier string) (*resource.ReadResponse, grantModel) {
	t.Helper()

	state := grantState(ctx, t, grantModelOf(tier))
	resp := &resource.ReadResponse{State: state}
	c.Read(ctx, resource.ReadRequest{State: state}, resp)

	var got grantModel

	if !resp.State.Raw.IsNull() {
		resp.State.Get(ctx, &got)
	}

	return resp, got
}

func TestGrantRead_FindsGranteeAcrossPages(t *testing.T) {
	t.Parallel()

	pages := 0

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnListGrants: func(req *vaultbrowsev1.ListGrantsRequest) (*vaultbrowsev1.ListGrantsResponse, error) {
			pages++

			if len(req.GetBase().GetPageParams().GetDirectionOrCursor().GetCursor()) == 0 {
				return &vaultbrowsev1.ListGrantsResponse{
					Grants:     []*vaultbrowsev1.Grant{{GranteeId: otherGrant, IdpId: directoryIDPID, Tier: authzv1.Tier_TIER_VIEW}},
					NextCursor: []byte("next"),
				}, nil
			}

			return &vaultbrowsev1.ListGrantsResponse{
				Grants: []*vaultbrowsev1.Grant{{GranteeId: testGrantee, IdpId: directoryIDPID, Tier: authzv1.Tier_TIER_EDIT}},
			}, nil
		},
	}})

	resp, got := readGrant(context.Background(), t, &grantResource{client: c}, "use")

	if resp.Diagnostics.HasError() || pages != 2 || got.Tier.ValueString() != "edit" {
		t.Fatalf("pages = %d, state = %+v, diags = %v", pages, got, resp.Diagnostics)
	}
}

func TestGrantRead_ClearsStateWhenGrantIsAbsentOrNodeGone(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		resp *vaultbrowsev1.ListGrantsResponse
		err  error
	}{
		"grantee absent":          {resp: &vaultbrowsev1.ListGrantsResponse{Grants: []*vaultbrowsev1.Grant{{GranteeId: otherGrant, IdpId: directoryIDPID}}}},
		"other identity provider": {resp: &vaultbrowsev1.ListGrantsResponse{Grants: []*vaultbrowsev1.Grant{{GranteeId: testGrantee, IdpId: "other"}}}},
		"node gone":               {err: connect.NewError(connect.CodeNotFound, errVaultNotFound)},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{OnListGrants: func(*vaultbrowsev1.ListGrantsRequest) (*vaultbrowsev1.ListGrantsResponse, error) {
				return tc.resp, tc.err
			}}})

			resp, _ := readGrant(context.Background(), t, &grantResource{client: c}, "use")

			if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
				t.Errorf("state should be removed; diags = %v", resp.Diagnostics)
			}
		})
	}
}

func TestGrantDelete_DeletesTheGrantee(t *testing.T) {
	t.Parallel()

	var got *vaultbrowsev1.DeleteGrantRequest

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnDeleteGrant: func(req *vaultbrowsev1.DeleteGrantRequest) (*vaultbrowsev1.DeleteGrantResponse, error) {
			got = req

			return &vaultbrowsev1.DeleteGrantResponse{}, nil
		},
	}})

	ctx := context.Background()
	resp := &resource.DeleteResponse{}

	(&grantResource{client: c}).Delete(ctx, resource.DeleteRequest{State: grantState(ctx, t, grantModelOf("use"))}, resp)

	base := got.GetBase()
	if resp.Diagnostics.HasError() || base.GetVaultId() != "vault-1" || base.GetNodeId() != "node-1" || base.GetGranteeId() != testGrantee {
		t.Errorf("request = %v, diags = %v", got, resp.Diagnostics)
	}
}

func TestGrantImport_ParsesVaultNodeAndGrantee(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := grantSchema(ctx, t).Schema
	empty := tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}

	resp := &resource.ImportStateResponse{State: empty}
	(&grantResource{}).ImportState(ctx, resource.ImportStateRequest{ID: "vault-1/node-1/" + otherGrant}, resp)

	var got grantModel

	resp.State.Get(ctx, &got)

	if resp.Diagnostics.HasError() || got.VaultID.ValueString() != "vault-1" || got.NodeID.ValueString() != "node-1" || got.Grantee.ValueString() != otherGrant {
		t.Errorf("state = %+v, diags = %v", got, resp.Diagnostics)
	}

	for _, bad := range []string{"", "vault-1", "vault-1/node-1", "vault-1//grantee", "/node/grantee"} {
		r := &resource.ImportStateResponse{State: empty}
		(&grantResource{}).ImportState(ctx, resource.ImportStateRequest{ID: bad}, r)

		if !r.Diagnostics.HasError() {
			t.Errorf("import id %q should be rejected", bad)
		}
	}
}
