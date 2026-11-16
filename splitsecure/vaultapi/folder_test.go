package vaultapi_test

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"

	"connectrpc.com/connect"

	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi/vaultfake"
)

func ensure(t *testing.T, f *vaultfake.FolderTree, path ...string) (string, error) {
	t.Helper()

	browse := &vaultfake.Browse{}
	f.Attach(browse)

	c := vaultfake.New(t, vaultfake.Handlers{Browse: browse})

	return vaultapi.EnsureFolder(context.Background(), c.VaultBrowse, "vault-1", path)
}

func TestEnsureFolder_ExistingPathCreatesNothing(t *testing.T) {
	t.Parallel()

	f := &vaultfake.FolderTree{Existing: map[string]string{"a": "id-a", "a/b": "id-b"}}

	got, err := ensure(t, f, "a", "b")
	if err != nil || got != "id-b" || len(f.Created()) != 0 {
		t.Fatalf("got %q, err %v, created %v", got, err, f.Created())
	}
}

func TestEnsureFolder_CreatesMissingSegmentsInOrder(t *testing.T) {
	t.Parallel()

	f := &vaultfake.FolderTree{Existing: map[string]string{"a": "id-a"}}

	got, err := ensure(t, f, "a", "b", "c")
	if err != nil {
		t.Fatalf("EnsureFolder: %v", err)
	}

	if got != "new-c" || !slices.Equal(f.Created(), []string{"b", "c"}) || !slices.Equal(f.Parents(), []string{"id-a", "new-b"}) {
		t.Errorf("got %q, created %v under %v", got, f.Created(), f.Parents())
	}
}

func TestEnsureFolder_CreatesWholePathUnderRoot(t *testing.T) {
	t.Parallel()

	f := &vaultfake.FolderTree{Existing: map[string]string{}}

	got, err := ensure(t, f, "a", "b")
	if err != nil || got != "new-b" || !slices.Equal(f.Parents(), []string{"", "new-a"}) {
		t.Fatalf("got %q, err %v, parents %v", got, err, f.Parents())
	}
}

func TestEnsureFolder_EmptyPathIsTheRoot(t *testing.T) {
	t.Parallel()

	f := &vaultfake.FolderTree{}

	got, err := ensure(t, f)
	if err != nil || got != "" || len(f.Created()) != 0 {
		t.Fatalf("got %q, err %v", got, err)
	}
}

func TestEnsureFolder_SurfacesCreateRefusal(t *testing.T) {
	t.Parallel()

	f := &vaultfake.FolderTree{Refuse: errRefused}

	_, err := ensure(t, f, "a")
	if err == nil || !strings.Contains(err.Error(), "permission_denied") {
		t.Fatalf("err = %v, want the refusal", err)
	}
}

func TestEnsureFolder_UsesFolderAnotherCreatorMadeFirst(t *testing.T) {
	t.Parallel()

	lookups := 0

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnListNodes: func(*vaultbrowsev1.ListNodesRequest) (*vaultbrowsev1.ListNodesResponse, error) {
			lookups++
			// The first lookup misses; a parallel apply creates the folder before the second.
			if lookups == 1 {
				return nil, connect.NewError(connect.CodeNotFound, errGone)
			}

			return &vaultbrowsev1.ListNodesResponse{ResolvedNodeId: "id-a"}, nil
		},
		OnCreateFolder: func(*vaultbrowsev1.CreateFolderRequest) (*vaultbrowsev1.CreateFolderResponse, error) {
			return nil, connect.NewError(connect.CodeAlreadyExists, errGone)
		},
	}})

	got, err := vaultapi.EnsureFolder(context.Background(), c.VaultBrowse, "vault-1", []string{"a"})
	if err != nil || got != "id-a" {
		t.Fatalf("got %q, err %v", got, err)
	}
}

func TestEnsureFolder_ConcurrentCallsShareOneFolder(t *testing.T) {
	t.Parallel()

	f := &vaultfake.FolderTree{}

	browse := &vaultfake.Browse{}
	f.Attach(browse)

	c := vaultfake.New(t, vaultfake.Handlers{Browse: browse})

	var wg sync.WaitGroup

	ids := make([]string, 2)

	for i := range ids {
		wg.Go(func() {
			id, err := vaultapi.EnsureFolder(context.Background(), c.VaultBrowse, "vault-1", []string{"a", "b"})
			if err != nil {
				t.Error(err)
			}

			ids[i] = id
		})
	}

	wg.Wait()

	if ids[0] == "" || ids[0] != ids[1] {
		t.Errorf("ids = %v, want one shared folder", ids)
	}
}

func TestFolderTree_RefusesDuplicateLabelUnderTheSameParent(t *testing.T) {
	t.Parallel()

	f := &vaultfake.FolderTree{}

	browse := &vaultfake.Browse{}
	f.Attach(browse)

	c := vaultfake.New(t, vaultfake.Handlers{Browse: browse})
	req := &vaultbrowsev1.CreateFolderRequest{Base: &vaultbrowsev1.CreateFolderRequest_Base{VaultId: "vault-1", Label: "a"}}

	_, err := c.VaultBrowse.CreateFolder(context.Background(), connect.NewRequest(req))
	if err != nil {
		t.Fatal(err)
	}

	_, err = c.VaultBrowse.CreateFolder(context.Background(), connect.NewRequest(req))
	if connect.CodeOf(err) != connect.CodeAlreadyExists {
		t.Fatalf("err = %v, want already exists", err)
	}
}
