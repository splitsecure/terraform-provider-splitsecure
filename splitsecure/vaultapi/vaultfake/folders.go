package vaultfake

import (
	"errors"
	"strings"
	"sync"

	"connectrpc.com/connect"

	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	vaulttypesv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaulttypes/v1"
)

var (
	errNoFolder     = errors.New("no such folder")
	errFolderExists = errors.New("folder already exists")
)

// FolderTree serves folder lookups and creation, one tree per vault id. New folders get the id "new-<label>".
type FolderTree struct {
	// Existing maps a slash-joined label path to its node id. It seeds every vault.
	Existing map[string]string
	// Refuse, when set, makes every CreateFolder answer permission denied.
	Refuse error
	// Nodes maps a node id to its label path from the root, ending with its own label. A node not listed sits at the root under its id.
	Nodes map[string][]string
	// Truncated makes GetNode cut every path, as a caller with a narrow grant sees it.
	Truncated bool

	mu      sync.Mutex
	made    map[string]map[string]string
	paths   map[string][]string
	created []string
	parents []string
}

// segmentsKey keys a label path on its segments, so a label holding a slash cannot collide with a deeper path.
func segmentsKey(segments []string) string {
	return strings.Join(segments, "\x00")
}

// Attach routes b's ListNodes and CreateFolder calls to the tree.
func (f *FolderTree) Attach(b *Browse) {
	b.OnListNodes = func(req *vaultbrowsev1.ListNodesRequest) (*vaultbrowsev1.ListNodesResponse, error) {
		f.mu.Lock()
		defer f.mu.Unlock()

		id, ok := f.lookup(req.GetBase().GetVaultId(), req.GetBase().GetLocator().GetLabelPath().GetSegments())
		if !ok {
			return nil, connect.NewError(connect.CodeNotFound, errNoFolder)
		}

		return &vaultbrowsev1.ListNodesResponse{ResolvedNodeId: id}, nil
	}

	b.OnGetNode = func(req *vaultbrowsev1.GetNodeRequest) (*vaultbrowsev1.GetNodeResponse, error) {
		f.mu.Lock()
		defer f.mu.Unlock()

		if segments := req.GetBase().GetLocator().GetLabelPath().GetSegments(); len(segments) > 0 {
			id, ok := f.lookup(req.GetBase().GetVaultId(), segments)
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

		vaultID := req.GetBase().GetVaultId()
		label := req.GetBase().GetLabel()
		parent := req.GetBase().GetLocator().GetParentNodeId()

		var path []string
		if parent != "" {
			path = f.pathOf(vaultID, parent)
		}

		path = append(append([]string(nil), path...), label)

		if _, exists := f.lookup(vaultID, path); exists {
			return nil, connect.NewError(connect.CodeAlreadyExists, errFolderExists)
		}

		id := "new-" + label

		if f.made == nil {
			f.made = map[string]map[string]string{}
			f.paths = map[string][]string{}
		}

		if f.made[vaultID] == nil {
			f.made[vaultID] = map[string]string{}
		}

		f.made[vaultID][segmentsKey(path)] = id
		f.paths[vaultID+"\x00"+id] = path
		f.created = append(f.created, label)
		f.parents = append(f.parents, parent)

		return &vaultbrowsev1.CreateFolderResponse{NodeId: id, ParentNodeId: parent}, nil
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

// lookup returns the id of the folder at segments in a vault. The caller holds f.mu.
func (f *FolderTree) lookup(vaultID string, segments []string) (string, bool) {
	if id, ok := f.made[vaultID][segmentsKey(segments)]; ok {
		return id, true
	}

	id, ok := f.Existing[strings.Join(segments, "/")]

	return id, ok
}

// pathOf returns the label path of a folder node id. The caller holds f.mu.
func (f *FolderTree) pathOf(vaultID, nodeID string) []string {
	if path, ok := f.paths[vaultID+"\x00"+nodeID]; ok {
		return path
	}

	for joined, id := range f.Existing {
		if id == nodeID {
			return strings.Split(joined, "/")
		}
	}

	if path, ok := f.Nodes[nodeID]; ok {
		return path
	}

	return []string{nodeID}
}

// AtRoot answers GetNode as if every node sits at the vault root under its own id.
func AtRoot(req *vaultbrowsev1.GetNodeRequest) (*vaultbrowsev1.GetNodeResponse, error) {
	nodeID := req.GetBase().GetLocator().GetParentNodeId()

	return &vaultbrowsev1.GetNodeResponse{Node: &vaulttypesv1.Node{NodeId: nodeID, Label: nodeID}, LabelPath: []string{nodeID}}, nil
}
