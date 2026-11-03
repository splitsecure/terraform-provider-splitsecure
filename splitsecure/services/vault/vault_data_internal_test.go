package vault

import (
	"context"
	"errors"
	"testing"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/datasource"

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

	if !resp.Schema.Attributes["label"].IsRequired() {
		t.Error("label should be Required")
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

	got, err := (&vaultDataSource{client: c}).findByLabel(context.Background(), "s2r:test:org:acme", "prod")
	if err != nil {
		t.Fatalf("findByLabel: %v", err)
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

	_, err := (&vaultDataSource{client: c}).findByLabel(context.Background(), "s2r:test:org:acme", "prod")
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

	_, err := (&vaultDataSource{client: c}).findByLabel(context.Background(), "s2r:test:org:acme", "prod")
	if !errors.Is(err, errVaultAmbig) {
		t.Fatalf("err = %v, want errVaultAmbig", err)
	}
}

func browseResolving(t *testing.T, resolved string, err error) *vaultfake.Browse {
	t.Helper()

	return &vaultfake.Browse{
		OnListNodes: func(req *vaultbrowsev1.ListNodesRequest) (*vaultbrowsev1.ListNodesResponse, error) {
			segments := req.GetBase().GetLocator().GetLabelPath().GetSegments()
			if len(segments) != 2 || segments[0] != "terraform" || segments[1] != "prod" || req.GetBase().GetVaultId() != "v1" {
				t.Errorf("unexpected request: %v", req)
			}

			return &vaultbrowsev1.ListNodesResponse{ResolvedNodeId: resolved}, err
		},
	}
}

func TestResolveFolder_ReturnsResolvedNodeID(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Browse: browseResolving(t, "node-9", nil)})

	got, err := (&vaultDataSource{client: c}).resolveFolder(context.Background(), "v1", []string{"terraform", "prod"})
	if err != nil {
		t.Fatalf("resolveFolder: %v", err)
	}

	if got != "node-9" {
		t.Errorf("node id = %q, want node-9", got)
	}
}

func TestResolveFolder_ErrorsWhenPathDoesNotResolve(t *testing.T) {
	t.Parallel()

	for name, browse := range map[string]*vaultfake.Browse{
		"not found code": browseResolving(t, "", connect.NewError(connect.CodeNotFound, errFolderNotFound)),
		"empty node id":  browseResolving(t, "", nil),
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := vaultfake.New(t, vaultfake.Handlers{Browse: browse})

			_, err := (&vaultDataSource{client: c}).resolveFolder(context.Background(), "v1", []string{"terraform", "prod"})
			if err == nil {
				t.Fatal("expected an error")
			}
		})
	}
}

func TestVaultSchema_FolderAttributes(t *testing.T) {
	t.Parallel()

	resp := &datasource.SchemaResponse{}
	NewVaultDataSource().Schema(context.Background(), datasource.SchemaRequest{}, resp)

	if !resp.Schema.Attributes["folder"].IsOptional() || !resp.Schema.Attributes["node_id"].IsComputed() {
		t.Error("folder should be Optional and node_id Computed")
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

	got, err := (&vaultDataSource{client: c}).findByLabel(context.Background(), "s2r:test:org:acme", "prod")
	if err != nil {
		t.Fatalf("findByLabel: %v", err)
	}

	if got.VaultID != "v2" || got.Summary != nil || len(got.Shared) != 2 {
		t.Errorf("match = %+v", got)
	}
}

func TestFindByLabel_DedupesVaultInBothLists(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Catalog: catalogWithShared(
		[]*vaultcatalogv1.VaultSummary{{VaultId: "v1", Label: "prod"}},
		sharedFolder("v1", "n1", "terraform"),
	)})

	got, err := (&vaultDataSource{client: c}).findByLabel(context.Background(), "s2r:test:org:acme", "prod")
	if err != nil {
		t.Fatalf("findByLabel: %v", err)
	}

	if got.Summary == nil || len(got.Shared) != 1 {
		t.Errorf("match = %+v", got)
	}
}

func TestFindByLabel_ErrorsOnSameLabelAcrossLists(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Catalog: catalogWithShared(
		[]*vaultcatalogv1.VaultSummary{{VaultId: "v1", Label: "prod"}},
		sharedFolder("v2", "n1", "terraform"),
	)})

	_, err := (&vaultDataSource{client: c}).findByLabel(context.Background(), "s2r:test:org:acme", "prod")
	if !errors.Is(err, errVaultAmbig) {
		t.Fatalf("err = %v, want errVaultAmbig", err)
	}
}

func TestResolveFolderIn_UsesSharedNodeForSingleSegment(t *testing.T) {
	t.Parallel()

	// No ListNodes handler: a call to it would be Unimplemented.
	c := vaultfake.New(t, vaultfake.Handlers{})
	match := &vaultMatch{VaultID: "v2", Shared: []*vaultcatalogv1.SharedNode{sharedFolder("v2", "n1", "terraform")}}

	got, err := (&vaultDataSource{client: c}).resolveFolderIn(context.Background(), match, []string{"terraform"})
	if err != nil {
		t.Fatalf("resolveFolderIn: %v", err)
	}

	if got != "n1" {
		t.Errorf("node id = %q, want n1", got)
	}
}

func TestResolveFolderIn_ListsNodesOtherwise(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Browse: browseResolving(t, "node-9", nil)})
	match := &vaultMatch{VaultID: "v1", Shared: []*vaultcatalogv1.SharedNode{sharedFolder("v1", "n1", "terraform")}}

	got, err := (&vaultDataSource{client: c}).resolveFolderIn(context.Background(), match, []string{"terraform", "prod"})
	if err != nil {
		t.Fatalf("resolveFolderIn: %v", err)
	}

	if got != "node-9" {
		t.Errorf("node id = %q, want node-9", got)
	}
}
