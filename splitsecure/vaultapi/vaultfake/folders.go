package vaultfake

import (
	"errors"
	"strings"
	"sync"

	"connectrpc.com/connect"

	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
)

var errNoFolder = errors.New("no such folder")

// FolderTree serves folder lookups and creation for a vault. New folders get the id "new-<label>".
type FolderTree struct {
	// Existing maps a slash-joined label path to its node id.
	Existing map[string]string
	// Refuse, when set, makes every CreateFolder answer permission denied.
	Refuse error

	mu      sync.Mutex
	created []string
	parents []string
}

// Attach routes b's ListNodes and CreateFolder calls to the tree.
func (f *FolderTree) Attach(b *Browse) {
	b.OnListNodes = func(req *vaultbrowsev1.ListNodesRequest) (*vaultbrowsev1.ListNodesResponse, error) {
		f.mu.Lock()
		defer f.mu.Unlock()

		id, ok := f.Existing[strings.Join(req.GetBase().GetLocator().GetLabelPath().GetSegments(), "/")]
		if !ok {
			return nil, connect.NewError(connect.CodeNotFound, errNoFolder)
		}

		return &vaultbrowsev1.ListNodesResponse{ResolvedNodeId: id}, nil
	}

	b.OnCreateFolder = func(req *vaultbrowsev1.CreateFolderRequest) (*vaultbrowsev1.CreateFolderResponse, error) {
		f.mu.Lock()
		defer f.mu.Unlock()

		if f.Refuse != nil {
			return nil, connect.NewError(connect.CodePermissionDenied, f.Refuse)
		}

		parent := req.GetBase().GetLocator().GetParentNodeId()
		f.created = append(f.created, req.GetBase().GetLabel())
		f.parents = append(f.parents, parent)

		return &vaultbrowsev1.CreateFolderResponse{NodeId: "new-" + req.GetBase().GetLabel(), ParentNodeId: parent}, nil
	}
}

// Created returns the labels of the folders created so far, in order.
func (f *FolderTree) Created() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.created...)
}

// Parents returns the parent node id of each created folder, in order. "" is the vault root.
func (f *FolderTree) Parents() []string {
	f.mu.Lock()
	defer f.mu.Unlock()

	return append([]string(nil), f.parents...)
}
