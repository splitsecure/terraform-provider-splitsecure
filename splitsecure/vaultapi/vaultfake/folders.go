package vaultfake

import (
	"errors"
	"strings"
	"sync"

	"connectrpc.com/connect"

	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	vaulttypesv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaulttypes/v1"
)

var errNoFolder = errors.New("no such folder")

// FolderTree serves folder lookups and creation for a vault. New folders get the id "new-<label>".
type FolderTree struct {
	// Existing maps a slash-joined label path to its node id.
	Existing map[string]string
	// Refuse, when set, makes every CreateFolder answer permission denied.
	Refuse error
	// Nodes maps a node id to its label path from the root, ending with its own label. A node not listed sits at the root under its id.
	Nodes map[string][]string
	// Truncated makes GetNode cut every path, as a caller with a narrow grant sees it.
	Truncated bool

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

	b.OnGetNode = func(req *vaultbrowsev1.GetNodeRequest) (*vaultbrowsev1.GetNodeResponse, error) {
		f.mu.Lock()
		defer f.mu.Unlock()

		if segments := req.GetBase().GetLocator().GetLabelPath().GetSegments(); len(segments) > 0 {
			id, ok := f.Existing[strings.Join(segments, "/")]
			if !ok {
				return nil, connect.NewError(connect.CodeNotFound, errNoFolder)
			}

			return &vaultbrowsev1.GetNodeResponse{Node: &vaulttypesv1.Node{NodeId: id, Label: segments[len(segments)-1], IsDir: true}, LabelPath: segments}, nil
		}

		nodeID := req.GetBase().GetLocator().GetParentNodeId()

		path, ok := f.Nodes[nodeID]
		if !ok {
			path = []string{nodeID}
		}

		return &vaultbrowsev1.GetNodeResponse{Node: &vaulttypesv1.Node{NodeId: nodeID, Label: path[len(path)-1]}, LabelPath: path, PathTruncated: f.Truncated}, nil
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

// AtRoot answers GetNode as if every node sits at the vault root under its own id.
func AtRoot(req *vaultbrowsev1.GetNodeRequest) (*vaultbrowsev1.GetNodeResponse, error) {
	nodeID := req.GetBase().GetLocator().GetParentNodeId()

	return &vaultbrowsev1.GetNodeResponse{Node: &vaulttypesv1.Node{NodeId: nodeID, Label: nodeID}, LabelPath: []string{nodeID}}, nil
}
