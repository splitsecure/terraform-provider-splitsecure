package connectedapp

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	pagev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/page/v1"
	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	"github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1/vaultbrowsev1connect"
	vaulttypesv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaulttypes/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
)

var errIssuerNotFound = errors.New("no SAML2 identity provider or OIDC issuer the caller can see in the app's vault signs for it")

// issuerMatch tells whether a record is the issuer an app is bound to.
type issuerMatch struct {
	kind  string
	match func(*vaultapi.Record) bool
}

func issuerMatchOf(app *pb.ConnectedAppParams) (issuerMatch, error) {
	if b := app.GetSaml2().GetBinding(); app.GetSaml2() != nil {
		return issuerMatch{kind: vaultapi.KindSAML2IDP, match: func(rec *vaultapi.Record) bool {
			idp, err := vaultapi.DecodeIdP(rec.Params)

			return err == nil && idp.GetIdpSerial() == b.GetIdpSerial()
		}}, nil
	}

	if b := app.GetOidc().GetBinding(); app.GetOidc() != nil {
		return issuerMatch{kind: vaultapi.KindWIFAuthority, match: func(rec *vaultapi.Record) bool {
			state, err := vaultapi.DecodeOIDCIssuer(rec.Params)

			return err == nil && state.GetAuthorityId() == b.GetAuthorityId()
		}}, nil
	}

	return issuerMatch{}, errNoBinding
}

// findIssuer returns the node id of the record that signs for app, searching every folder of the vault the caller can see.
func findIssuer(ctx context.Context, browse vaultbrowsev1connect.VaultBrowseServiceClient, vaultID string, app *pb.ConnectedAppParams) (string, error) {
	m, err := issuerMatchOf(app)
	if err != nil {
		return "", err
	}

	id, err := searchFolder(ctx, browse, vaultID, "", m)
	if err != nil {
		return "", err
	}

	if id == "" {
		return "", errIssuerNotFound
	}

	return id, nil
}

// searchFolder walks one folder, the root when folderID is empty, and the folders below it. A folder the caller cannot see is skipped.
func searchFolder(ctx context.Context, browse vaultbrowsev1connect.VaultBrowseServiceClient, vaultID, folderID string, m issuerMatch) (string, error) {
	var cursor []byte

	for {
		children, next, err := listPage(ctx, browse, vaultID, folderID, cursor)
		if vaultapi.IsNotFound(err) {
			return "", nil
		}

		if err != nil {
			return "", err
		}

		for _, child := range children {
			id, err := searchNode(ctx, browse, vaultID, child, m)
			if err != nil || id != "" {
				return id, err
			}
		}

		if len(next) == 0 {
			return "", nil
		}

		cursor = next
	}
}

func searchNode(ctx context.Context, browse vaultbrowsev1connect.VaultBrowseServiceClient, vaultID string, node *vaulttypesv1.Node, m issuerMatch) (string, error) {
	if node.GetIsDir() {
		return searchFolder(ctx, browse, vaultID, node.GetNodeId(), m)
	}

	if node.GetRecord().GetKind() != m.kind {
		return "", nil
	}

	rec, err := vaultapi.FetchRecord(ctx, browse, vaultID, node.GetNodeId())
	if vaultapi.IsNotFound(err) {
		return "", nil
	}

	if err != nil {
		return "", fmt.Errorf("reading issuer candidate %s: %w", node.GetNodeId(), err)
	}

	if m.match(rec) {
		return node.GetNodeId(), nil
	}

	return "", nil
}

func listPage(ctx context.Context, browse vaultbrowsev1connect.VaultBrowseServiceClient, vaultID, folderID string, cursor []byte) ([]*vaulttypesv1.Node, []byte, error) {
	base := &vaultbrowsev1.ListNodesRequest_Base{VaultId: vaultID}

	if folderID != "" {
		base.Locator = &vaultbrowsev1.NodeLocator{Union: &vaultbrowsev1.NodeLocator_ParentNodeId{ParentNodeId: folderID}}
	}

	if cursor != nil {
		base.Page = &pagev1.PageParams{DirectionOrCursor: &pagev1.PageParams_DirectionOrCursor{
			Union: &pagev1.PageParams_DirectionOrCursor_Cursor{Cursor: cursor},
		}}
	}

	resp, err := browse.ListNodes(ctx, connect.NewRequest(&vaultbrowsev1.ListNodesRequest{Base: base}))
	if err != nil {
		return nil, nil, fmt.Errorf("listing folder %q: %w", folderID, err)
	}

	return resp.Msg.GetChildren(), resp.Msg.GetNextCursor(), nil
}
