package vault

import (
	"context"
	"testing"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	vaulttypesv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaulttypes/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi/vaultfake"
)

func folderSchema(ctx context.Context, t *testing.T) resource.SchemaResponse {
	t.Helper()

	resp := resource.SchemaResponse{}
	NewFolderResource().Schema(ctx, resource.SchemaRequest{}, &resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}

	return resp
}

func folderState(ctx context.Context, t *testing.T, m *folderModel) tfsdk.State {
	t.Helper()

	s := folderSchema(ctx, t).Schema
	state := tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}

	if diags := state.Set(ctx, m); diags.HasError() {
		t.Fatalf("building state: %v", diags)
	}

	return state
}

func folderPlan(ctx context.Context, t *testing.T, m *folderModel) tfsdk.Plan {
	t.Helper()

	state := folderState(ctx, t, m)

	return tfsdk.Plan{Schema: state.Schema, Raw: state.Raw}
}

func existingFolder(name, parent string) *folderModel {
	m := &folderModel{ID: types.StringValue("f1"), VaultID: types.StringValue("vault-1"), Name: types.StringValue(name), ParentID: types.StringNull()}
	if parent != "" {
		m.ParentID = types.StringValue(parent)
	}

	return m
}

func TestFolderSchema_Attributes(t *testing.T) {
	t.Parallel()

	s := folderSchema(context.Background(), t).Schema

	for _, name := range []string{"vault_id", "name"} {
		if !s.Attributes[name].IsRequired() {
			t.Errorf("%q should be Required", name)
		}
	}

	if !s.Attributes["parent_id"].IsOptional() || !s.Attributes["id"].IsComputed() {
		t.Error("parent_id should be Optional and id Computed")
	}
}

func TestFolderCreate_PlacesFolderUnderParentOrRoot(t *testing.T) {
	t.Parallel()

	for name, parent := range map[string]string{"under a parent": "p1", "at the root": ""} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var got *vaultbrowsev1.CreateFolderRequest

			c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
				OnCreateFolder: func(req *vaultbrowsev1.CreateFolderRequest) (*vaultbrowsev1.CreateFolderResponse, error) {
					got = req

					return &vaultbrowsev1.CreateFolderResponse{NodeId: "f1"}, nil
				},
			}})

			ctx := context.Background()
			plan := existingFolder("prod", parent)
			plan.ID = types.StringUnknown()

			resp := &resource.CreateResponse{State: folderState(ctx, t, existingFolder("", ""))}
			(&folderResource{client: c}).Create(ctx, resource.CreateRequest{Plan: folderPlan(ctx, t, plan)}, resp)

			if resp.Diagnostics.HasError() {
				t.Fatalf("Create: %v", resp.Diagnostics)
			}

			if got.GetBase().GetLabel() != "prod" || got.GetBase().GetLocator().GetParentNodeId() != parent {
				t.Errorf("request = %v", got)
			}

			var state folderModel

			resp.State.Get(ctx, &state)

			if state.ID.ValueString() != "f1" {
				t.Errorf("id = %q", state.ID.ValueString())
			}
		})
	}
}

func nodeResponse(label string, path []string, truncated bool) *vaultbrowsev1.GetNodeResponse {
	return &vaultbrowsev1.GetNodeResponse{
		Node:          &vaulttypesv1.Node{NodeId: "f1", Label: label, IsDir: true},
		LabelPath:     path,
		PathTruncated: truncated,
	}
}

func TestFolderRead_RefreshesNameAndParent(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnGetNode: func(req *vaultbrowsev1.GetNodeRequest) (*vaultbrowsev1.GetNodeResponse, error) {
			if req.GetBase().GetLocator().GetParentNodeId() == "f1" {
				return nodeResponse("renamed", []string{"terraform", "renamed"}, false), nil
			}

			// The parent lookup by label path.
			return &vaultbrowsev1.GetNodeResponse{Node: &vaulttypesv1.Node{NodeId: "p9", Label: "terraform"}}, nil
		},
	}})

	ctx := context.Background()
	state := folderState(ctx, t, existingFolder("prod", "p1"))
	resp := &resource.ReadResponse{State: state}

	(&folderResource{client: c}).Read(ctx, resource.ReadRequest{State: state}, resp)

	var got folderModel

	resp.State.Get(ctx, &got)

	if resp.Diagnostics.HasError() || got.Name.ValueString() != "renamed" || got.ParentID.ValueString() != "p9" {
		t.Fatalf("state = %+v, diags = %v", got, resp.Diagnostics)
	}
}

func TestFolderRead_KeepsParentWhenPathIsCutOrAtRoot(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		node   *vaultbrowsev1.GetNodeResponse
		prior  *folderModel
		parent types.String
	}{
		"path truncated keeps the prior parent": {nodeResponse("prod", []string{"prod"}, true), existingFolder("prod", "p1"), types.StringValue("p1")},
		"root parent keeps unset null":          {nodeResponse("prod", []string{"prod"}, false), existingFolder("prod", ""), types.StringNull()},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
				OnGetNode: func(*vaultbrowsev1.GetNodeRequest) (*vaultbrowsev1.GetNodeResponse, error) { return tc.node, nil },
			}})

			ctx := context.Background()
			state := folderState(ctx, t, tc.prior)
			resp := &resource.ReadResponse{State: state}

			(&folderResource{client: c}).Read(ctx, resource.ReadRequest{State: state}, resp)

			var got folderModel

			resp.State.Get(ctx, &got)

			if resp.Diagnostics.HasError() || !got.ParentID.Equal(tc.parent) {
				t.Errorf("parent = %v, want %v, diags = %v", got.ParentID, tc.parent, resp.Diagnostics)
			}
		})
	}
}

func TestFolderRead_ClearsStateWhenFolderIsGone(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnGetNode: func(*vaultbrowsev1.GetNodeRequest) (*vaultbrowsev1.GetNodeResponse, error) {
			return nil, connect.NewError(connect.CodeNotFound, errVaultNotFound)
		},
	}})

	ctx := context.Background()
	state := folderState(ctx, t, existingFolder("prod", ""))
	resp := &resource.ReadResponse{State: state}

	(&folderResource{client: c}).Read(ctx, resource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
		t.Errorf("state should be removed; diags = %v", resp.Diagnostics)
	}
}

func updateFolder(ctx context.Context, t *testing.T, c *folderResource, from, to *folderModel) {
	t.Helper()

	resp := &resource.UpdateResponse{State: folderState(ctx, t, from)}
	c.Update(ctx, resource.UpdateRequest{Plan: folderPlan(ctx, t, to), State: folderState(ctx, t, from)}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Update: %v", resp.Diagnostics)
	}
}

func TestFolderUpdate_RenamesInPlace(t *testing.T) {
	t.Parallel()

	var renamed *vaultbrowsev1.RenameNodeRequest

	moves := 0

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnRenameNode: func(req *vaultbrowsev1.RenameNodeRequest) (*vaultbrowsev1.RenameNodeResponse, error) {
			renamed = req

			return &vaultbrowsev1.RenameNodeResponse{}, nil
		},
		OnMoveNode: func(*vaultbrowsev1.MoveNodeRequest) (*vaultbrowsev1.MoveNodeResponse, error) {
			moves++

			return &vaultbrowsev1.MoveNodeResponse{}, nil
		},
	}})

	updateFolder(context.Background(), t, &folderResource{client: c}, existingFolder("prod", "p1"), existingFolder("staging", "p1"))

	if renamed.GetBase().GetNodeId() != "f1" || renamed.GetBase().GetNewLabel() != "staging" || moves != 0 {
		t.Errorf("rename = %v, moves = %d", renamed, moves)
	}
}

func TestFolderUpdate_MovesInPlace(t *testing.T) {
	t.Parallel()

	var moved *vaultbrowsev1.MoveNodeRequest

	renames := 0

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnRenameNode: func(*vaultbrowsev1.RenameNodeRequest) (*vaultbrowsev1.RenameNodeResponse, error) {
			renames++

			return &vaultbrowsev1.RenameNodeResponse{}, nil
		},
		OnMoveNode: func(req *vaultbrowsev1.MoveNodeRequest) (*vaultbrowsev1.MoveNodeResponse, error) {
			moved = req

			return &vaultbrowsev1.MoveNodeResponse{}, nil
		},
	}})

	r := &folderResource{client: c}
	ctx := context.Background()

	updateFolder(ctx, t, r, existingFolder("prod", "p1"), existingFolder("prod", "p2"))

	if moved.GetBase().GetNodeId() != "f1" || moved.GetBase().GetLocator().GetParentNodeId() != "p2" || renames != 0 {
		t.Errorf("move = %v, renames = %d", moved, renames)
	}

	// Moving to the root leaves the locator unset.
	updateFolder(ctx, t, r, existingFolder("prod", "p2"), existingFolder("prod", ""))

	if moved.GetBase().GetLocator() != nil {
		t.Errorf("root move locator = %v, want unset", moved.GetBase().GetLocator())
	}
}

func TestFolderDelete_DeletesByNodeID(t *testing.T) {
	t.Parallel()

	var got *vaultbrowsev1.DeleteFolderRequest

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnDeleteFolder: func(req *vaultbrowsev1.DeleteFolderRequest) (*vaultbrowsev1.DeleteFolderResponse, error) {
			got = req

			return &vaultbrowsev1.DeleteFolderResponse{ReparentedChildCount: 2}, nil
		},
	}})

	ctx := context.Background()
	resp := &resource.DeleteResponse{}

	(&folderResource{client: c}).Delete(ctx, resource.DeleteRequest{State: folderState(ctx, t, existingFolder("prod", ""))}, resp)

	if resp.Diagnostics.HasError() || got.GetBase().GetVaultId() != "vault-1" || got.GetBase().GetLocator().GetParentNodeId() != "f1" {
		t.Errorf("request = %v, diags = %v", got, resp.Diagnostics)
	}
}

func TestFolderImport_SplitsVaultAndID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	s := folderSchema(ctx, t).Schema

	resp := &resource.ImportStateResponse{State: tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}}
	(&folderResource{}).ImportState(ctx, resource.ImportStateRequest{ID: "vault-1/f1"}, resp)

	var got folderModel

	resp.State.Get(ctx, &got)

	if resp.Diagnostics.HasError() || got.VaultID.ValueString() != "vault-1" || got.ID.ValueString() != "f1" {
		t.Errorf("state = %+v, diags = %v", got, resp.Diagnostics)
	}

	bad := &resource.ImportStateResponse{State: resp.State}
	(&folderResource{}).ImportState(ctx, resource.ImportStateRequest{ID: "nope"}, bad)

	if !bad.Diagnostics.HasError() {
		t.Error("expected an error for a malformed import id")
	}
}
