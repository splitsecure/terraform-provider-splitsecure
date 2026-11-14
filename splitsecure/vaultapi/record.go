package vaultapi

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	saml2v3 "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/saml2/v3"
	wifv2 "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/wif/v2"
	issuancev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/issuance/v1"
	teamresourcev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/teamresource/v1"
	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	"github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1/vaultbrowsev1connect"
)

// Record kinds named by Issuance.resource.kind.
const (
	KindSAML2IDP     = "saml2-idp"
	KindWIFAuthority = "wif-authority"
)

// Record is the part of an attested record the provider resources read.
type Record struct {
	Kind       string
	Params     []byte
	Revision   uint32
	Attributes *teamresourcev1.BaseResourceAttributes
	Materials  []*issuancev1.MaterialBinding
}

// FetchRecord reads and decodes the attested issuance of one vault record.
func FetchRecord(ctx context.Context, c vaultbrowsev1connect.VaultBrowseServiceClient, vaultID, nodeID string) (*Record, error) {
	resp, err := c.GetRecord(ctx, connect.NewRequest(&vaultbrowsev1.GetRecordRequest{
		Base: &vaultbrowsev1.GetRecordRequest_Base{
			VaultId: vaultID,
			NodeId:  nodeID,
		},
	}))
	if err != nil {
		return nil, fmt.Errorf("getting record: %w", err)
	}

	var issuance issuancev1.Issuance

	err = proto.Unmarshal(resp.Msg.GetAttested().GetIssuance(), &issuance)
	if err != nil {
		return nil, fmt.Errorf("decoding issuance: %w", err)
	}

	return &Record{
		Kind:       issuance.GetResource().GetKind(),
		Params:     issuance.GetParams(),
		Revision:   resp.Msg.GetRevision(),
		Attributes: issuance.GetResource().GetBaseResourceAttributes(),
		Materials:  issuance.GetUse().GetMaterials(),
	}, nil
}

// IsNotFound reports whether err is a not-found answer from the server.
func IsNotFound(err error) bool {
	return err != nil && connect.CodeOf(err) == connect.CodeNotFound
}

// DecodeIdP decodes the params of a saml2-idp record.
func DecodeIdP(params []byte) (*saml2v3.IdPParams, error) { //nolint:revive // IdP matches the proto name IdPParams.
	var idp saml2v3.IdPParams

	err := proto.Unmarshal(params, &idp)
	if err != nil {
		return nil, fmt.Errorf("decoding IdP params: %w", err)
	}

	return &idp, nil
}

// DecodeOIDCIssuer decodes the params of a wif-authority record.
func DecodeOIDCIssuer(params []byte) (*wifv2.WorkloadIdentityAuthorityState, error) {
	var state wifv2.WorkloadIdentityAuthorityState

	err := proto.Unmarshal(params, &state)
	if err != nil {
		return nil, fmt.Errorf("decoding OIDC issuer params: %w", err)
	}

	return &state, nil
}
