package saml2

import (
	"context"
	"errors"
	"testing"
	"time"

	"connectrpc.com/connect"

	conveniencestorev1 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/conveniencestore/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/conveniencestore/v1/conveniencestorev1connect"
	enclavev1 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/enclave/v1"
	enclaveroundtripv1 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/enclaveroundtrip/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/enclaveroundtrip/v1/enclaveroundtripv1connect"
	proposalsv1 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/proposals/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/proposals/v1/proposalsv1connect"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

// Compact aliases keep the fake-method signatures readable. Each
// resolves to the connect-go request / response pair for the named
// RPC.
type (
	sendReq      = connect.Request[enclaveroundtripv1.SendRequest]
	sendResp     = connect.Response[enclaveroundtripv1.SendResponse]
	gp4rReq      = connect.Request[enclaveroundtripv1.GetProposalForRequestRequest]
	gp4rResp     = connect.Response[enclaveroundtripv1.GetProposalForRequestResponse]
	getPropReq   = connect.Request[proposalsv1.GetProposalRequest]
	getPropResp  = connect.Response[proposalsv1.GetProposalResponse]
	getResReq    = connect.Request[conveniencestorev1.GetProposalResourceRequest]
	getResResp   = connect.Response[conveniencestorev1.GetProposalResourceResponse]
	getSAML2Req  = connect.Request[conveniencestorev1.GetSAML2ResourcesRequest]
	getSAML2Resp = connect.Response[conveniencestorev1.GetSAML2ResourcesResponse]
)

// fakeERTSClient embeds the EnclaveRoundtripServiceClient interface so
// only the methods the tests exercise need a stub. Calling an
// un-overridden method nil-derefs the embedded interface, which fails
// the test loud and clear.
type fakeERTSClient struct {
	enclaveroundtripv1connect.EnclaveRoundtripServiceClient

	sendFn        func(ctx context.Context, req *sendReq) (*sendResp, error)
	getProposalFn func(ctx context.Context, req *gp4rReq) (*gp4rResp, error)
}

func (f *fakeERTSClient) Send(ctx context.Context, req *sendReq) (*sendResp, error) {
	return f.sendFn(ctx, req)
}

func (f *fakeERTSClient) GetProposalForRequest(ctx context.Context, req *gp4rReq) (*gp4rResp, error) {
	return f.getProposalFn(ctx, req)
}

type fakeProposalsClient struct {
	proposalsv1connect.ProposalsServiceClient

	getProposalFn func(ctx context.Context, req *getPropReq) (*getPropResp, error)
}

func (f *fakeProposalsClient) GetProposal(ctx context.Context, req *getPropReq) (*getPropResp, error) {
	return f.getProposalFn(ctx, req)
}

type fakeConvenienceStoreClient struct {
	conveniencestorev1connect.ConvenienceStoreServiceClient

	getProposalResourceFn func(ctx context.Context, req *getResReq) (*getResResp, error)
	getSAML2ResourcesFn   func(ctx context.Context, req *getSAML2Req) (*getSAML2Resp, error)
}

func (f *fakeConvenienceStoreClient) GetProposalResource(ctx context.Context, req *getResReq) (*getResResp, error) {
	return f.getProposalResourceFn(ctx, req)
}

func (f *fakeConvenienceStoreClient) GetSAML2Resources(ctx context.Context, req *getSAML2Req) (*getSAML2Resp, error) {
	return f.getSAML2ResourcesFn(ctx, req)
}

func TestSendAndAwaitResource_HappyPath(t *testing.T) {
	t.Parallel()

	wantRequestID := []byte("req-1")
	wantProposalID := []byte("prop-1")
	wantResourceS2R := "s2r:us:saml2idp:t/r"

	c := &client.Client{
		EnclaveRoundtripService: &fakeERTSClient{
			sendFn: func(_ context.Context, req *sendReq) (*sendResp, error) {
				if req.Msg.GetBase().GetNewProposalScopedEnclave() != "s2r:us:org:foo" {
					t.Errorf("Send target = %q, want s2r:us:org:foo", req.Msg.GetBase().GetNewProposalScopedEnclave())
				}

				return connect.NewResponse(&enclaveroundtripv1.SendResponse{RequestId: wantRequestID}), nil
			},
			getProposalFn: func(_ context.Context, _ *gp4rReq) (*gp4rResp, error) {
				return connect.NewResponse(&enclaveroundtripv1.GetProposalForRequestResponse{ProposalId: wantProposalID}), nil
			},
		},
		ProposalsService: &fakeProposalsClient{
			getProposalFn: func(_ context.Context, _ *getPropReq) (*getPropResp, error) {
				return connect.NewResponse(&proposalsv1.GetProposalResponse{
					Metadata: &proposalsv1.ProposalMetadata{
						Status: &proposalsv1.ProposalStatus{Status: &proposalsv1.ProposalStatus_Completed_{Completed: &proposalsv1.ProposalStatus_Completed{}}},
					},
				}), nil
			},
		},
		ConvenienceStoreService: &fakeConvenienceStoreClient{
			getProposalResourceFn: func(_ context.Context, _ *getResReq) (*getResResp, error) {
				return connect.NewResponse(&conveniencestorev1.GetProposalResourceResponse{ResourceS2R: wantResourceS2R}), nil
			},
		},
	}

	got, err := sendAndAwaitResource(context.Background(), c, "s2r:us:org:foo", &enclavev1.InvokeRequest{}, time.Second)
	if err != nil {
		t.Fatalf("sendAndAwaitResource: %v", err)
	}
	if got != wantResourceS2R {
		t.Fatalf("got %q, want %q", got, wantResourceS2R)
	}
}

func TestSendAndAwaitResource_RejectedProposal(t *testing.T) {
	t.Parallel()

	c := &client.Client{
		EnclaveRoundtripService: &fakeERTSClient{
			sendFn: func(_ context.Context, _ *sendReq) (*sendResp, error) {
				return connect.NewResponse(&enclaveroundtripv1.SendResponse{RequestId: []byte("req")}), nil
			},
			getProposalFn: func(_ context.Context, _ *gp4rReq) (*gp4rResp, error) {
				return connect.NewResponse(&enclaveroundtripv1.GetProposalForRequestResponse{ProposalId: []byte("prop")}), nil
			},
		},
		ProposalsService: &fakeProposalsClient{
			getProposalFn: func(_ context.Context, _ *getPropReq) (*getPropResp, error) {
				return connect.NewResponse(&proposalsv1.GetProposalResponse{
					Metadata: &proposalsv1.ProposalMetadata{
						Status: &proposalsv1.ProposalStatus{
							Status: &proposalsv1.ProposalStatus_Error_{Error: &proposalsv1.ProposalStatus_Error{Message: "voter rejected"}},
						},
					},
				}), nil
			},
		},
	}

	_, err := sendAndAwaitResource(context.Background(), c, "s2r:us:org:foo", &enclavev1.InvokeRequest{}, time.Second)
	if err == nil {
		t.Fatal("sendAndAwaitResource succeeded; want error")
	}
	if !errors.Is(err, errProposalRejected) {
		t.Fatalf("error = %v, want errProposalRejected wrapping", err)
	}
}

func TestSendAndAwaitResource_OrgRequired(t *testing.T) {
	t.Parallel()

	_, err := sendAndAwaitResource(context.Background(), &client.Client{}, "", &enclavev1.InvokeRequest{}, time.Second)
	if !errors.Is(err, errOrgS2RRequired) {
		t.Fatalf("error = %v, want errOrgS2RRequired", err)
	}
}

func TestSendAndAwaitDelete_HappyPath(t *testing.T) {
	t.Parallel()

	c := &client.Client{
		EnclaveRoundtripService: &fakeERTSClient{
			sendFn: func(_ context.Context, _ *sendReq) (*sendResp, error) {
				return connect.NewResponse(&enclaveroundtripv1.SendResponse{RequestId: []byte("req")}), nil
			},
			getProposalFn: func(_ context.Context, _ *gp4rReq) (*gp4rResp, error) {
				return connect.NewResponse(&enclaveroundtripv1.GetProposalForRequestResponse{ProposalId: []byte("prop")}), nil
			},
		},
		ProposalsService: &fakeProposalsClient{
			getProposalFn: func(_ context.Context, _ *getPropReq) (*getPropResp, error) {
				return connect.NewResponse(&proposalsv1.GetProposalResponse{
					Metadata: &proposalsv1.ProposalMetadata{
						Status: &proposalsv1.ProposalStatus{Status: &proposalsv1.ProposalStatus_Completed_{Completed: &proposalsv1.ProposalStatus_Completed{}}},
					},
				}), nil
			},
		},
	}

	err := sendAndAwaitDelete(context.Background(), c, "s2r:us:org:foo", &enclavev1.InvokeRequest{}, time.Second)
	if err != nil {
		t.Fatalf("sendAndAwaitDelete: %v", err)
	}
}

func TestFetchSAML2Record(t *testing.T) {
	t.Parallel()

	const target = "s2r:us:saml2idp:t/r"
	rec := &conveniencestorev1.SAML2ResourceRecord{}

	c := &client.Client{
		ConvenienceStoreService: &fakeConvenienceStoreClient{
			getSAML2ResourcesFn: func(_ context.Context, req *getSAML2Req) (*getSAML2Resp, error) {
				if got := req.Msg.GetBase().GetResourceS2Rs(); len(got) != 1 || got[0] != target {
					t.Errorf("ResourceS2Rs = %v, want [%q]", got, target)
				}

				return connect.NewResponse(&conveniencestorev1.GetSAML2ResourcesResponse{Resources: map[string]*conveniencestorev1.SAML2ResourceRecord{target: rec}}), nil
			},
		},
	}

	got, err := fetchSAML2Record(context.Background(), c, target)
	if err != nil {
		t.Fatalf("fetchSAML2Record: %v", err)
	}
	if got != rec {
		t.Fatalf("got %p, want %p", got, rec)
	}
}

func TestFetchSAML2Record_NotFound(t *testing.T) {
	t.Parallel()

	c := &client.Client{
		ConvenienceStoreService: &fakeConvenienceStoreClient{
			getSAML2ResourcesFn: func(_ context.Context, _ *getSAML2Req) (*getSAML2Resp, error) {
				return connect.NewResponse(&conveniencestorev1.GetSAML2ResourcesResponse{Resources: map[string]*conveniencestorev1.SAML2ResourceRecord{}}), nil
			},
		},
	}

	got, err := fetchSAML2Record(context.Background(), c, "s2r:us:saml2idp:t/r")
	if err != nil {
		t.Fatalf("fetchSAML2Record: %v", err)
	}
	if got != nil {
		t.Fatalf("got %v, want nil", got)
	}
}
