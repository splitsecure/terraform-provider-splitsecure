// Package vaultfake serves the vault API over an in-process HTTP server so tests can run real Connect calls against canned handlers.
package vaultfake

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	issuancev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/issuance/v1"
	teamresourcev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/teamresource/v1"

	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	"github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1/vaultbrowsev1connect"
	vaultcatalogv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultcatalog/v1"
	"github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultcatalog/v1/vaultcatalogv1connect"
	vaultusev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1"
	"github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1/vaultusev1connect"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

// Use answers VaultUseService calls with the matching On field. An unset field answers Unimplemented.
type Use struct {
	vaultusev1connect.UnimplementedVaultUseServiceHandler

	OnCreateSAML2IDP     func(*vaultusev1.CreateSAML2IDPRequest) (*vaultusev1.CreateSAML2IDPResponse, error)
	OnCreateWIFAuthority func(*vaultusev1.CreateWIFAuthorityRequest) (*vaultusev1.CreateWIFAuthorityResponse, error)
	OnCreateConnectedApp func(*vaultusev1.CreateConnectedAppRequest) (*vaultusev1.CreateConnectedAppResponse, error)
	OnDelete             func(*vaultusev1.DeleteRequest) (*vaultusev1.DeleteResponse, error)
	OnPollTicket         func(*vaultusev1.PollTicketRequest) (*vaultusev1.PollTicketResponse, error)
	OnCancel             func(*vaultusev1.CancelRequest) (*vaultusev1.CancelResponse, error)
}

// CreateSAML2IDP implements vaultusev1connect.VaultUseServiceHandler.
func (u *Use) CreateSAML2IDP(ctx context.Context, req *connect.Request[vaultusev1.CreateSAML2IDPRequest]) (*connect.Response[vaultusev1.CreateSAML2IDPResponse], error) {
	if u.OnCreateSAML2IDP == nil {
		return u.UnimplementedVaultUseServiceHandler.CreateSAML2IDP(ctx, req)
	}

	resp, err := u.OnCreateSAML2IDP(req.Msg)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(resp), nil
}

// CreateWIFAuthority implements vaultusev1connect.VaultUseServiceHandler.
func (u *Use) CreateWIFAuthority(ctx context.Context, req *connect.Request[vaultusev1.CreateWIFAuthorityRequest]) (*connect.Response[vaultusev1.CreateWIFAuthorityResponse], error) {
	if u.OnCreateWIFAuthority == nil {
		return u.UnimplementedVaultUseServiceHandler.CreateWIFAuthority(ctx, req)
	}

	resp, err := u.OnCreateWIFAuthority(req.Msg)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(resp), nil
}

// CreateConnectedApp implements vaultusev1connect.VaultUseServiceHandler.
func (u *Use) CreateConnectedApp(ctx context.Context, req *connect.Request[vaultusev1.CreateConnectedAppRequest]) (*connect.Response[vaultusev1.CreateConnectedAppResponse], error) {
	if u.OnCreateConnectedApp == nil {
		return u.UnimplementedVaultUseServiceHandler.CreateConnectedApp(ctx, req)
	}

	resp, err := u.OnCreateConnectedApp(req.Msg)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(resp), nil
}

// Delete implements vaultusev1connect.VaultUseServiceHandler.
func (u *Use) Delete(ctx context.Context, req *connect.Request[vaultusev1.DeleteRequest]) (*connect.Response[vaultusev1.DeleteResponse], error) {
	if u.OnDelete == nil {
		return u.UnimplementedVaultUseServiceHandler.Delete(ctx, req)
	}

	resp, err := u.OnDelete(req.Msg)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(resp), nil
}

// PollTicket implements vaultusev1connect.VaultUseServiceHandler.
func (u *Use) PollTicket(ctx context.Context, req *connect.Request[vaultusev1.PollTicketRequest]) (*connect.Response[vaultusev1.PollTicketResponse], error) {
	if u.OnPollTicket == nil {
		return u.UnimplementedVaultUseServiceHandler.PollTicket(ctx, req)
	}

	resp, err := u.OnPollTicket(req.Msg)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(resp), nil
}

// Browse answers VaultBrowseService calls with the matching On field.
type Browse struct {
	vaultbrowsev1connect.UnimplementedVaultBrowseServiceHandler

	OnGetRecord     func(*vaultbrowsev1.GetRecordRequest) (*vaultbrowsev1.GetRecordResponse, error)
	OnListNodes     func(*vaultbrowsev1.ListNodesRequest) (*vaultbrowsev1.ListNodesResponse, error)
	OnDescribeVault func(*vaultbrowsev1.DescribeVaultRequest) (*vaultbrowsev1.DescribeVaultResponse, error)
	OnCreateFolder  func(*vaultbrowsev1.CreateFolderRequest) (*vaultbrowsev1.CreateFolderResponse, error)
}

// GetRecord implements vaultbrowsev1connect.VaultBrowseServiceHandler.
func (b *Browse) GetRecord(ctx context.Context, req *connect.Request[vaultbrowsev1.GetRecordRequest]) (*connect.Response[vaultbrowsev1.GetRecordResponse], error) {
	if b.OnGetRecord == nil {
		return b.UnimplementedVaultBrowseServiceHandler.GetRecord(ctx, req)
	}

	resp, err := b.OnGetRecord(req.Msg)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(resp), nil
}

// Catalog answers VaultCatalogService calls with the matching On field.
type Catalog struct {
	vaultcatalogv1connect.UnimplementedVaultCatalogServiceHandler

	OnListVaults       func(*vaultcatalogv1.ListVaultsRequest) (*vaultcatalogv1.ListVaultsResponse, error)
	OnListSharedWithMe func(*vaultcatalogv1.ListSharedWithMeRequest) (*vaultcatalogv1.ListSharedWithMeResponse, error)
}

// ListVaults implements vaultcatalogv1connect.VaultCatalogServiceHandler.
func (c *Catalog) ListVaults(ctx context.Context, req *connect.Request[vaultcatalogv1.ListVaultsRequest]) (*connect.Response[vaultcatalogv1.ListVaultsResponse], error) {
	if c.OnListVaults == nil {
		return c.UnimplementedVaultCatalogServiceHandler.ListVaults(ctx, req)
	}

	resp, err := c.OnListVaults(req.Msg)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(resp), nil
}

// Handlers are the canned services a test serves. A nil field serves an empty handler.
type Handlers struct {
	Use     *Use
	Browse  *Browse
	Catalog *Catalog
}

// New serves h until the test ends and returns a client wired to it.
func New(t *testing.T, h Handlers) *client.Client {
	t.Helper()

	if h.Use == nil {
		h.Use = &Use{}
	}

	if h.Browse == nil {
		h.Browse = &Browse{}
	}

	if h.Catalog == nil {
		h.Catalog = &Catalog{}
	}

	mux := http.NewServeMux()
	mux.Handle(vaultusev1connect.NewVaultUseServiceHandler(h.Use))
	mux.Handle(vaultbrowsev1connect.NewVaultBrowseServiceHandler(h.Browse))
	mux.Handle(vaultcatalogv1connect.NewVaultCatalogServiceHandler(h.Catalog))

	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)

	return &client.Client{
		VaultUse:     vaultusev1connect.NewVaultUseServiceClient(srv.Client(), srv.URL),
		VaultBrowse:  vaultbrowsev1connect.NewVaultBrowseServiceClient(srv.Client(), srv.URL),
		VaultCatalog: vaultcatalogv1connect.NewVaultCatalogServiceClient(srv.Client(), srv.URL),
		OrgS2R:       "s2r:test:org:acme",
	}
}

// Record builds a GetRecord response carrying a serialized issuance of the given kind, attributes, params and bound materials.
func Record(t *testing.T, kind string, attrs *teamresourcev1.BaseResourceAttributes, params proto.Message, materials ...*issuancev1.MaterialBinding) *vaultbrowsev1.GetRecordResponse {
	t.Helper()

	rawParams, err := proto.Marshal(params)
	if err != nil {
		t.Fatalf("marshalling params: %v", err)
	}

	raw, err := proto.Marshal(&issuancev1.Issuance{
		Resource: &issuancev1.ResourceView{Kind: kind, BaseResourceAttributes: attrs},
		Use:      &issuancev1.UseView{Materials: materials},
		Params:   rawParams,
	})
	if err != nil {
		t.Fatalf("marshalling issuance: %v", err)
	}

	return &vaultbrowsev1.GetRecordResponse{Attested: &issuancev1.Attested{Issuance: raw}, Revision: 1}
}

// CreateOutcome answers a create inline with secretID, or with a ticket when viaTicket is set.
func CreateOutcome(viaTicket bool, secretID string) *vaultusev1.CreateOutcome {
	if viaTicket {
		return &vaultusev1.CreateOutcome{Union: &vaultusev1.CreateOutcome_Ticket{Ticket: &vaultusev1.Ticket{TicketId: []byte("ticket")}}}
	}

	return &vaultusev1.CreateOutcome{Union: &vaultusev1.CreateOutcome_Result{Result: &vaultusev1.CreateResult{SecretId: secretID}}}
}

// DeleteOutcome answers a delete inline, or with a ticket when viaTicket is set.
func DeleteOutcome(viaTicket bool) *vaultusev1.DeleteOutcome {
	if viaTicket {
		return &vaultusev1.DeleteOutcome{Union: &vaultusev1.DeleteOutcome_Ticket{Ticket: &vaultusev1.Ticket{TicketId: []byte("ticket")}}}
	}

	return &vaultusev1.DeleteOutcome{Union: &vaultusev1.DeleteOutcome_Result{Result: &vaultusev1.DeleteResult{}}}
}

// ResolvedTicket answers a poll with the create result for secretID, or with a delete result when forDelete is set.
func ResolvedTicket(forDelete bool, secretID string) *vaultusev1.PollTicketResponse {
	if forDelete {
		return &vaultusev1.PollTicketResponse{Outcome: &vaultusev1.TicketOutcome{
			Outcome: &vaultusev1.TicketOutcome_DeleteResult{DeleteResult: &vaultusev1.DeleteResult{}},
		}}
	}

	return &vaultusev1.PollTicketResponse{Outcome: &vaultusev1.TicketOutcome{
		Outcome: &vaultusev1.TicketOutcome_CreateResult{CreateResult: &vaultusev1.CreateResult{SecretId: secretID}},
	}}
}

// ListNodes implements vaultbrowsev1connect.VaultBrowseServiceHandler.
func (b *Browse) ListNodes(ctx context.Context, req *connect.Request[vaultbrowsev1.ListNodesRequest]) (*connect.Response[vaultbrowsev1.ListNodesResponse], error) {
	if b.OnListNodes == nil {
		return b.UnimplementedVaultBrowseServiceHandler.ListNodes(ctx, req)
	}

	resp, err := b.OnListNodes(req.Msg)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(resp), nil
}

// ListSharedWithMe implements vaultcatalogv1connect.VaultCatalogServiceHandler.
func (c *Catalog) ListSharedWithMe(ctx context.Context, req *connect.Request[vaultcatalogv1.ListSharedWithMeRequest]) (*connect.Response[vaultcatalogv1.ListSharedWithMeResponse], error) {
	if c.OnListSharedWithMe == nil {
		return c.UnimplementedVaultCatalogServiceHandler.ListSharedWithMe(ctx, req)
	}

	resp, err := c.OnListSharedWithMe(req.Msg)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(resp), nil
}

// DescribeVault implements vaultbrowsev1connect.VaultBrowseServiceHandler.
func (b *Browse) DescribeVault(ctx context.Context, req *connect.Request[vaultbrowsev1.DescribeVaultRequest]) (*connect.Response[vaultbrowsev1.DescribeVaultResponse], error) {
	if b.OnDescribeVault == nil {
		return b.UnimplementedVaultBrowseServiceHandler.DescribeVault(ctx, req)
	}

	resp, err := b.OnDescribeVault(req.Msg)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(resp), nil
}

// Cancel implements vaultusev1connect.VaultUseServiceHandler.
func (u *Use) Cancel(ctx context.Context, req *connect.Request[vaultusev1.CancelRequest]) (*connect.Response[vaultusev1.CancelResponse], error) {
	if u.OnCancel == nil {
		return u.UnimplementedVaultUseServiceHandler.Cancel(ctx, req)
	}

	resp, err := u.OnCancel(req.Msg)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(resp), nil
}

// CreateFolder implements vaultbrowsev1connect.VaultBrowseServiceHandler.
func (b *Browse) CreateFolder(ctx context.Context, req *connect.Request[vaultbrowsev1.CreateFolderRequest]) (*connect.Response[vaultbrowsev1.CreateFolderResponse], error) {
	if b.OnCreateFolder == nil {
		return b.UnimplementedVaultBrowseServiceHandler.CreateFolder(ctx, req)
	}

	resp, err := b.OnCreateFolder(req.Msg)
	if err != nil {
		return nil, err
	}

	return connect.NewResponse(resp), nil
}
