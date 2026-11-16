package vault

import (
	"context"
	"slices"
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

const callerS2R = "s2r:us:sa:caller"

// grantStore is a node's direct grants, served two per page.
type grantStore struct {
	grants  map[string]authzv1.Tier
	puts    map[authzv1.Tier][]string
	deleted []string
}

func newGrantStore(grants map[string]authzv1.Tier) *grantStore {
	return &grantStore{grants: grants, puts: map[authzv1.Tier][]string{}}
}

func (s *grantStore) browse() *vaultfake.Browse {
	return &vaultfake.Browse{
		OnListGrants: func(req *vaultbrowsev1.ListGrantsRequest) (*vaultbrowsev1.ListGrantsResponse, error) {
			grantees := make([]string, 0, len(s.grants))
			for g := range s.grants {
				grantees = append(grantees, g)
			}

			slices.Sort(grantees)

			from := 0
			if cursor := req.GetBase().GetPageParams().GetDirectionOrCursor().GetCursor(); len(cursor) > 0 {
				from = int(cursor[0])
			}

			resp := &vaultbrowsev1.ListGrantsResponse{}

			for _, g := range grantees[from:min(from+2, len(grantees))] {
				resp.Grants = append(resp.Grants, &vaultbrowsev1.Grant{NodeId: req.GetBase().GetNodeId(), GranteeId: g, IdpId: directoryIDPID, Tier: s.grants[g]})
			}

			if from+2 < len(grantees) {
				resp.NextCursor = []byte{byte(from + 2)}
			}

			return resp, nil
		},
		OnPutGrants: func(req *vaultbrowsev1.PutGrantsRequest) (*vaultbrowsev1.PutGrantsResponse, error) {
			for _, g := range req.GetBase().GetGranteeIds() {
				s.grants[g] = req.GetBase().GetTier()
				s.puts[req.GetBase().GetTier()] = append(s.puts[req.GetBase().GetTier()], g)
			}

			return &vaultbrowsev1.PutGrantsResponse{}, nil
		},
		OnDeleteGrant: func(req *vaultbrowsev1.DeleteGrantRequest) (*vaultbrowsev1.DeleteGrantResponse, error) {
			delete(s.grants, req.GetBase().GetGranteeId())

			s.deleted = append(s.deleted, req.GetBase().GetGranteeId())

			return &vaultbrowsev1.DeleteGrantResponse{}, nil
		},
	}
}

func nodeGrantsResourceFor(t *testing.T, s *grantStore) *nodeGrantsResource {
	t.Helper()

	c := vaultfake.New(t, vaultfake.Handlers{Browse: s.browse()})
	c.PrincipalS2R = callerS2R

	return &nodeGrantsResource{client: c}
}

func nodeGrantsModelOf(t *testing.T, grants map[string]string) *nodeGrantsModel {
	t.Helper()

	elems := make([]nodeGrantModel, 0, len(grants))
	for g, tier := range grants {
		elems = append(elems, nodeGrantModel{Grantee: types.StringValue(g), Tier: types.StringValue(tier)})
	}

	return nodeGrantsModelWith(t, elems)
}

func nodeGrantsModelWith(t *testing.T, elems []nodeGrantModel) *nodeGrantsModel {
	t.Helper()

	set, diags := types.SetValueFrom(context.Background(), nodeGrantType(), elems)
	if diags.HasError() {
		t.Fatalf("building grant set: %v", diags)
	}

	return &nodeGrantsModel{ID: types.StringUnknown(), VaultID: types.StringValue("vault-1"), NodeID: types.StringValue("node-1"), Grant: set}
}

func nodeGrantsState(ctx context.Context, t *testing.T, m *nodeGrantsModel) tfsdk.State {
	t.Helper()

	resp := resource.SchemaResponse{}
	NewNodeGrantsResource().Schema(ctx, resource.SchemaRequest{}, &resp)

	state := tfsdk.State{Schema: resp.Schema, Raw: tftypes.NewValue(resp.Schema.Type().TerraformType(ctx), nil)}

	if diags := state.Set(ctx, m); diags.HasError() {
		t.Fatalf("building state: %v", diags)
	}

	return state
}

func grantsOn(t *testing.T, state tfsdk.State) map[string]string {
	t.Helper()

	var m nodeGrantsModel

	if diags := state.Get(context.Background(), &m); diags.HasError() {
		t.Fatalf("reading state: %v", diags)
	}

	declared, err := declaredGrants(context.Background(), m.Grant)
	if err != nil {
		t.Fatalf("declaredGrants: %v", err)
	}

	tiers := make(map[string]string, len(declared))
	for key, g := range declared {
		tiers[key.grantee] = g.Tier.ValueString()
	}

	return tiers
}

func TestNodeGrantsSchema_Shape(t *testing.T) {
	t.Parallel()

	resp := resource.SchemaResponse{}
	NewNodeGrantsResource().Schema(context.Background(), resource.SchemaRequest{}, &resp)

	if !resp.Schema.Attributes["vault_id"].IsRequired() || !resp.Schema.Attributes["node_id"].IsRequired() {
		t.Error("vault_id and node_id should be Required")
	}

	if _, ok := resp.Schema.Blocks["grant"]; !ok {
		t.Error("grant block missing")
	}
}

func TestNodeGrantsCreate_ConvergesToTheDeclaredSet(t *testing.T) {
	t.Parallel()

	store := newGrantStore(map[string]authzv1.Tier{
		callerS2R:   authzv1.Tier_TIER_EDIT,
		"s2r:us:a":  authzv1.Tier_TIER_VIEW,
		"s2r:us:b":  authzv1.Tier_TIER_USE,
		"s2r:us:zz": authzv1.Tier_TIER_USE,
	})
	r := nodeGrantsResourceFor(t, store)
	ctx := context.Background()

	plan := nodeGrantsState(ctx, t, nodeGrantsModelOf(t, map[string]string{"s2r:us:a": "use", "s2r:us:b": "use", "s2r:us:c": "view"}))
	resp := &resource.CreateResponse{State: nodeGrantsState(ctx, t, nodeGrantsModelOf(t, nil))}

	r.Create(ctx, resource.CreateRequest{Plan: tfsdk.Plan{Schema: plan.Schema, Raw: plan.Raw}}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Create: %v", resp.Diagnostics)
	}

	want := map[string]authzv1.Tier{callerS2R: authzv1.Tier_TIER_EDIT, "s2r:us:a": authzv1.Tier_TIER_USE, "s2r:us:b": authzv1.Tier_TIER_USE, "s2r:us:c": authzv1.Tier_TIER_VIEW}
	if len(store.grants) != len(want) {
		t.Fatalf("grants = %v, want %v", store.grants, want)
	}

	for g, tier := range want {
		if store.grants[g] != tier {
			t.Errorf("grant of %s = %v, want %v", g, store.grants[g], tier)
		}
	}

	// b was already at use, so only a changes tier; c is new at view.
	if !slices.Equal(store.puts[authzv1.Tier_TIER_USE], []string{"s2r:us:a"}) || !slices.Equal(store.puts[authzv1.Tier_TIER_VIEW], []string{"s2r:us:c"}) {
		t.Errorf("puts = %v", store.puts)
	}

	if !slices.Equal(store.deleted, []string{"s2r:us:zz"}) {
		t.Errorf("deleted = %v, want only the extra grant", store.deleted)
	}
}

func TestNodeGrantsUpdate_KeepsTheCallersGrantEvenWhenUndeclared(t *testing.T) {
	t.Parallel()

	store := newGrantStore(map[string]authzv1.Tier{callerS2R: authzv1.Tier_TIER_EDIT, "s2r:us:a": authzv1.Tier_TIER_VIEW})
	r := nodeGrantsResourceFor(t, store)
	ctx := context.Background()

	plan := nodeGrantsState(ctx, t, nodeGrantsModelOf(t, map[string]string{}))
	resp := &resource.UpdateResponse{State: plan}

	r.Update(ctx, resource.UpdateRequest{Plan: tfsdk.Plan{Schema: plan.Schema, Raw: plan.Raw}, State: plan}, resp)

	if resp.Diagnostics.HasError() || !slices.Equal(store.deleted, []string{"s2r:us:a"}) || store.grants[callerS2R] != authzv1.Tier_TIER_EDIT {
		t.Errorf("deleted = %v, grants = %v, diags = %v", store.deleted, store.grants, resp.Diagnostics)
	}
}

func TestNodeGrantsRead_IgnoresTheCallersGrantAndSeesDrift(t *testing.T) {
	t.Parallel()

	store := newGrantStore(map[string]authzv1.Tier{callerS2R: authzv1.Tier_TIER_EDIT, "s2r:us:a": authzv1.Tier_TIER_USE, "s2r:us:x": authzv1.Tier_TIER_VIEW})
	r := nodeGrantsResourceFor(t, store)
	ctx := context.Background()

	state := nodeGrantsState(ctx, t, nodeGrantsModelOf(t, map[string]string{"s2r:us:a": "use"}))
	resp := &resource.ReadResponse{State: state}

	r.Read(ctx, resource.ReadRequest{State: state}, resp)

	got := grantsOn(t, resp.State)

	// The caller never shows; the grant added out of band does.
	if resp.Diagnostics.HasError() || len(got) != 2 || got["s2r:us:a"] != "use" || got["s2r:us:x"] != "view" {
		t.Errorf("grants = %v, diags = %v", got, resp.Diagnostics)
	}
}

func TestNodeGrantsRead_ShowsTheCallersGrantWhenDeclared(t *testing.T) {
	t.Parallel()

	store := newGrantStore(map[string]authzv1.Tier{callerS2R: authzv1.Tier_TIER_EDIT})
	r := nodeGrantsResourceFor(t, store)
	ctx := context.Background()

	state := nodeGrantsState(ctx, t, nodeGrantsModelOf(t, map[string]string{callerS2R: "use"}))
	resp := &resource.ReadResponse{State: state}

	r.Read(ctx, resource.ReadRequest{State: state}, resp)

	if got := grantsOn(t, resp.State); got[callerS2R] != "edit" {
		t.Errorf("grants = %v, want the declared caller grant refreshed to edit", got)
	}
}

func TestNodeGrantsRead_ClearsStateWhenNodeIsGone(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnListGrants: func(*vaultbrowsev1.ListGrantsRequest) (*vaultbrowsev1.ListGrantsResponse, error) {
			return nil, connect.NewError(connect.CodeNotFound, errVaultNotFound)
		},
	}})

	ctx := context.Background()
	state := nodeGrantsState(ctx, t, nodeGrantsModelOf(t, map[string]string{"s2r:us:a": "use"}))
	resp := &resource.ReadResponse{State: state}

	(&nodeGrantsResource{client: c}).Read(ctx, resource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
		t.Errorf("state should be removed; diags = %v", resp.Diagnostics)
	}
}

func TestNodeGrantsDelete_RemovesOnlyTheDeclaredGrants(t *testing.T) {
	t.Parallel()

	store := newGrantStore(map[string]authzv1.Tier{callerS2R: authzv1.Tier_TIER_EDIT, "s2r:us:a": authzv1.Tier_TIER_USE, "s2r:us:other": authzv1.Tier_TIER_VIEW})
	r := nodeGrantsResourceFor(t, store)
	ctx := context.Background()
	resp := &resource.DeleteResponse{}

	r.Delete(ctx, resource.DeleteRequest{State: nodeGrantsState(ctx, t, nodeGrantsModelOf(t, map[string]string{"s2r:us:a": "use", callerS2R: "edit"}))}, resp)

	if resp.Diagnostics.HasError() || !slices.Equal(store.deleted, []string{"s2r:us:a"}) {
		t.Errorf("deleted = %v, diags = %v", store.deleted, resp.Diagnostics)
	}
}

func TestNodeGrantsApply_RefusesAGranteeDeclaredTwice(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	set, _ := types.SetValueFrom(ctx, nodeGrantType(), []nodeGrantModel{
		{Grantee: types.StringValue("s2r:us:a"), Tier: types.StringValue("use")},
		{Grantee: types.StringValue("s2r:us:a"), Tier: types.StringValue("view")},
	})

	_, err := declaredGrants(ctx, set)
	if err == nil {
		t.Error("expected an error for a grantee in two blocks")
	}
}

func TestNodeGrantsImport_ParsesVaultAndNode(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	empty := nodeGrantsState(ctx, t, nodeGrantsModelOf(t, nil))
	empty.Raw = tftypes.NewValue(empty.Schema.Type().TerraformType(ctx), nil)

	resp := &resource.ImportStateResponse{State: empty}
	(&nodeGrantsResource{}).ImportState(ctx, resource.ImportStateRequest{ID: "vault-1/node-1"}, resp)

	var got nodeGrantsModel

	resp.State.Get(ctx, &got)

	if resp.Diagnostics.HasError() || got.VaultID.ValueString() != "vault-1" || got.NodeID.ValueString() != "node-1" {
		t.Errorf("state = %+v, diags = %v", got, resp.Diagnostics)
	}

	bad := &resource.ImportStateResponse{State: empty}
	(&nodeGrantsResource{}).ImportState(ctx, resource.ImportStateRequest{ID: "nope"}, bad)

	if !bad.Diagnostics.HasError() {
		t.Error("expected an error for a malformed import id")
	}
}

func TestNodeGrantsUpdate_RefusesToLowerTheCallersOwnGrant(t *testing.T) {
	t.Parallel()

	store := newGrantStore(map[string]authzv1.Tier{callerS2R: authzv1.Tier_TIER_EDIT, "s2r:us:x": authzv1.Tier_TIER_VIEW})
	r := nodeGrantsResourceFor(t, store)
	ctx := context.Background()

	plan := nodeGrantsState(ctx, t, nodeGrantsModelOf(t, map[string]string{callerS2R: "view"}))
	resp := &resource.UpdateResponse{State: plan}

	r.Update(ctx, resource.UpdateRequest{Plan: tfsdk.Plan{Schema: plan.Schema, Raw: plan.Raw}, State: plan}, resp)

	if !resp.Diagnostics.HasError() {
		t.Fatal("expected an error for a caller grant below edit")
	}

	if len(store.puts) != 0 || len(store.deleted) != 0 || store.grants[callerS2R] != authzv1.Tier_TIER_EDIT {
		t.Errorf("writes ran before the refusal: puts = %v, deleted = %v, grants = %v", store.puts, store.deleted, store.grants)
	}
}

func twoIDPBrowse() *vaultfake.Browse {
	return &vaultfake.Browse{
		OnListGrants: func(*vaultbrowsev1.ListGrantsRequest) (*vaultbrowsev1.ListGrantsResponse, error) {
			return &vaultbrowsev1.ListGrantsResponse{Grants: []*vaultbrowsev1.Grant{
				{GranteeId: "s2r:us:user:a", IdpId: directoryIDPID, Tier: authzv1.Tier_TIER_EDIT},
				{GranteeId: "s2r:us:user:a", IdpId: "okta", Tier: authzv1.Tier_TIER_VIEW},
			}}, nil
		},
	}
}

func TestNodeGrantsRead_KeepsOneGrantPerIdentityProvider(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Browse: twoIDPBrowse()})
	c.PrincipalS2R = callerS2R
	r := &nodeGrantsResource{client: c}
	ctx := context.Background()

	state := nodeGrantsState(ctx, t, nodeGrantsModelOf(t, map[string]string{"s2r:us:user:a": "edit"}))

	first := &resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, first)

	if first.Diagnostics.HasError() {
		t.Fatalf("first Read: %v", first.Diagnostics)
	}

	second := &resource.ReadResponse{State: first.State}
	r.Read(ctx, resource.ReadRequest{State: first.State}, second)

	if second.Diagnostics.HasError() {
		t.Fatalf("second Read refuses the state the first wrote: %v", second.Diagnostics)
	}

	var got nodeGrantsModel

	second.State.Get(ctx, &got)

	declared, err := declaredGrants(ctx, got.Grant)
	if err != nil || len(declared) != 2 {
		t.Fatalf("declared = %v, err = %v", declared, err)
	}

	if g := declared[newGrantKey("s2r:us:user:a", "")]; g.Tier.ValueString() != "edit" || !g.IDPID.IsNull() {
		t.Errorf("directory grant = %+v, want edit with a null idp_id", g)
	}

	if g := declared[newGrantKey("s2r:us:user:a", "okta")]; g.Tier.ValueString() != "view" || g.IDPID.ValueString() != "okta" {
		t.Errorf("okta grant = %+v, want view under okta", g)
	}
}

func TestNodeGrantsUpdate_SendsEachGrantsIdentityProviderAndRemovesFirst(t *testing.T) {
	t.Parallel()

	var calls []string

	browse := &vaultfake.Browse{
		OnListGrants: func(*vaultbrowsev1.ListGrantsRequest) (*vaultbrowsev1.ListGrantsResponse, error) {
			return &vaultbrowsev1.ListGrantsResponse{Grants: []*vaultbrowsev1.Grant{
				{GranteeId: "s2r:us:user:a", IdpId: "okta", Tier: authzv1.Tier_TIER_VIEW},
				{GranteeId: "s2r:us:user:b", IdpId: directoryIDPID, Tier: authzv1.Tier_TIER_USE},
			}}, nil
		},
		OnPutGrants: func(req *vaultbrowsev1.PutGrantsRequest) (*vaultbrowsev1.PutGrantsResponse, error) {
			calls = append(calls, "put:"+req.GetBase().GetIdpId()+":"+req.GetBase().GetGranteeIds()[0])

			return &vaultbrowsev1.PutGrantsResponse{}, nil
		},
		OnDeleteGrant: func(req *vaultbrowsev1.DeleteGrantRequest) (*vaultbrowsev1.DeleteGrantResponse, error) {
			calls = append(calls, "delete:"+req.GetBase().GetIdpId()+":"+req.GetBase().GetGranteeId())

			return &vaultbrowsev1.DeleteGrantResponse{}, nil
		},
	}

	c := vaultfake.New(t, vaultfake.Handlers{Browse: browse})
	c.PrincipalS2R = callerS2R
	r := &nodeGrantsResource{client: c}
	ctx := context.Background()

	plan := nodeGrantsState(ctx, t, nodeGrantsModelWith(t, []nodeGrantModel{
		{Grantee: types.StringValue("s2r:us:user:a"), Tier: types.StringValue("use"), IDPID: types.StringValue("okta")},
	}))
	resp := &resource.UpdateResponse{State: plan}

	r.Update(ctx, resource.UpdateRequest{Plan: tfsdk.Plan{Schema: plan.Schema, Raw: plan.Raw}, State: plan}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Update: %v", resp.Diagnostics)
	}

	want := []string{"delete:" + directoryIDPID + ":s2r:us:user:b", "put:okta:s2r:us:user:a"}
	if !slices.Equal(calls, want) {
		t.Errorf("calls = %v, want %v", calls, want)
	}
}

func TestNodeGrantsApply_AcceptsAGranteeUnderTwoIdentityProviders(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	set, diags := types.SetValueFrom(ctx, nodeGrantType(), []nodeGrantModel{
		{Grantee: types.StringValue("s2r:us:a"), Tier: types.StringValue("use")},
		{Grantee: types.StringValue("s2r:us:a"), Tier: types.StringValue("view"), IDPID: types.StringValue("okta")},
	})
	if diags.HasError() {
		t.Fatalf("building grant set: %v", diags)
	}

	declared, err := declaredGrants(ctx, set)
	if err != nil || len(declared) != 2 {
		t.Errorf("declared = %v, err = %v", declared, err)
	}
}
