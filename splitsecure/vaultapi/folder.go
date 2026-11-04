package vaultapi

import (
	"context"
	"fmt"

	"connectrpc.com/connect"

	pagev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/page/v1"
	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	"github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1/vaultbrowsev1connect"
)

// EnsureFolder returns the node id of the folder at path, creating the missing folders like mkdir -p.
// An empty path returns "", which places a record at the vault root.
func EnsureFolder(ctx context.Context, c vaultbrowsev1connect.VaultBrowseServiceClient, vaultID string, path []string) (string, error) {
	if len(path) == 0 {
		return "", nil
	}

	// Longest existing prefix first: the common case is a folder that already exists, which costs one call.
	existing := len(path)
	parentID := ""

	for ; existing > 0; existing-- {
		id, found, err := resolvePath(ctx, c, vaultID, path[:existing])
		if err != nil {
			return "", err
		}

		if found {
			parentID = id

			break
		}
	}

	for i := existing; i < len(path); i++ {
		id, err := createFolder(ctx, c, vaultID, parentID, path[:i+1])
		if err != nil {
			return "", err
		}

		parentID = id
	}

	return parentID, nil
}

func resolvePath(ctx context.Context, c vaultbrowsev1connect.VaultBrowseServiceClient, vaultID string, path []string) (string, bool, error) {
	resp, err := c.ListNodes(ctx, connect.NewRequest(&vaultbrowsev1.ListNodesRequest{
		Base: &vaultbrowsev1.ListNodesRequest_Base{
			VaultId: vaultID,
			Locator: &vaultbrowsev1.NodeLocator{
				Union: &vaultbrowsev1.NodeLocator_LabelPath{LabelPath: &vaultbrowsev1.LabelPath{Segments: path}},
			},
			Page: &pagev1.PageParams{Limit: 1},
		},
	}))
	if IsNotFound(err) {
		return "", false, nil
	}

	if err != nil {
		return "", false, fmt.Errorf("resolving folder %q: %w", path, err)
	}

	return resp.Msg.GetResolvedNodeId(), resp.Msg.GetResolvedNodeId() != "", nil
}

// createFolder creates the last segment of path under parentID. A concurrent creator winning the race is not an error.
func createFolder(ctx context.Context, c vaultbrowsev1connect.VaultBrowseServiceClient, vaultID, parentID string, path []string) (string, error) {
	base := &vaultbrowsev1.CreateFolderRequest_Base{
		VaultId: vaultID,
		Label:   path[len(path)-1],
	}

	if parentID != "" {
		base.Locator = &vaultbrowsev1.NodeLocator{Union: &vaultbrowsev1.NodeLocator_ParentNodeId{ParentNodeId: parentID}}
	}

	resp, err := c.CreateFolder(ctx, connect.NewRequest(&vaultbrowsev1.CreateFolderRequest{Base: base}))
	if connect.CodeOf(err) == connect.CodeAlreadyExists {
		id, found, resolveErr := resolvePath(ctx, c, vaultID, path)
		if resolveErr == nil && found {
			return id, nil
		}
	}

	if err != nil {
		return "", fmt.Errorf("creating folder %q: %w", path, err)
	}

	return resp.Msg.GetNodeId(), nil
}

// MoveNode moves a node under parentID, or under the vault root when parentID is empty.
func MoveNode(ctx context.Context, c vaultbrowsev1connect.VaultBrowseServiceClient, vaultID, nodeID, parentID string) error {
	base := &vaultbrowsev1.MoveNodeRequest_Base{VaultId: vaultID, NodeId: nodeID}

	if parentID != "" {
		base.Locator = &vaultbrowsev1.NodeLocator{Union: &vaultbrowsev1.NodeLocator_ParentNodeId{ParentNodeId: parentID}}
	}

	_, err := c.MoveNode(ctx, connect.NewRequest(&vaultbrowsev1.MoveNodeRequest{Base: base}))
	if err != nil {
		return fmt.Errorf("moving node: %w", err)
	}

	return nil
}
