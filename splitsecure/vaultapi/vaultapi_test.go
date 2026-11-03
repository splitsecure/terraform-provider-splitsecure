package vaultapi_test

import (
	"context"
	"errors"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/proto"

	saml2v3 "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/saml2/v3"
	wifv2 "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/wif/v2"
	keysv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/keys/v1"
	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	vaultusev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi/vaultfake"
)

func ticketOutcome() *vaultusev1.CreateOutcome {
	return &vaultusev1.CreateOutcome{Union: &vaultusev1.CreateOutcome_Ticket{Ticket: &vaultusev1.Ticket{TicketId: []byte("t1")}}}
}

func pollStatus(status *vaultusev1.TicketStatus) *vaultusev1.PollTicketResponse {
	return &vaultusev1.PollTicketResponse{Outcome: &vaultusev1.TicketOutcome{Outcome: &vaultusev1.TicketOutcome_Status{Status: status}}}
}

func TestAwaitCreate_InlineResult(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{})
	outcome := &vaultusev1.CreateOutcome{Union: &vaultusev1.CreateOutcome_Result{Result: &vaultusev1.CreateResult{SecretId: "node-1", Revision: 3}}}

	got, err := vaultapi.AwaitCreate(context.Background(), c.VaultUse, "vault-1", outcome)
	if err != nil {
		t.Fatalf("AwaitCreate: %v", err)
	}

	if got.GetSecretId() != "node-1" || got.GetRevision() != 3 {
		t.Errorf("result = %v", got)
	}
}

func TestAwaitCreate_TicketThenResult(t *testing.T) {
	t.Parallel()

	var seen *vaultusev1.PollTicketRequest

	c := vaultfake.New(t, vaultfake.Handlers{Use: &vaultfake.Use{
		OnPollTicket: func(req *vaultusev1.PollTicketRequest) (*vaultusev1.PollTicketResponse, error) {
			seen = req

			return &vaultusev1.PollTicketResponse{Outcome: &vaultusev1.TicketOutcome{
				Outcome: &vaultusev1.TicketOutcome_CreateResult{CreateResult: &vaultusev1.CreateResult{SecretId: "node-2"}},
			}}, nil
		},
	}})

	got, err := vaultapi.AwaitCreate(context.Background(), c.VaultUse, "vault-1", ticketOutcome())
	if err != nil {
		t.Fatalf("AwaitCreate: %v", err)
	}

	if got.GetSecretId() != "node-2" {
		t.Errorf("secret id = %q", got.GetSecretId())
	}

	if seen.GetBase().GetVaultId() != "vault-1" || string(seen.GetBase().GetTicketId()) != "t1" {
		t.Errorf("poll request = %v", seen)
	}
}

func TestAwaitCreate_TerminalStatuses(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name   string
		status *vaultusev1.TicketStatus
		want   error
		text   string
	}{
		{
			name:   "denied",
			status: &vaultusev1.TicketStatus{State: &vaultusev1.TicketStatus_Denied_{Denied: &vaultusev1.TicketStatus_Denied{Reason: "too risky"}}},
			want:   vaultapi.ErrDenied,
			text:   "too risky",
		},
		{
			name:   "expired",
			status: &vaultusev1.TicketStatus{State: &vaultusev1.TicketStatus_Expired_{Expired: &vaultusev1.TicketStatus_Expired{}}},
			want:   vaultapi.ErrExpired,
		},
		{
			name:   "cancelled",
			status: &vaultusev1.TicketStatus{State: &vaultusev1.TicketStatus_Cancelled_{Cancelled: &vaultusev1.TicketStatus_Cancelled{}}},
			want:   vaultapi.ErrCancelled,
		},
		{
			name:   "release expired",
			status: &vaultusev1.TicketStatus{State: &vaultusev1.TicketStatus_ReleaseExpired_{ReleaseExpired: &vaultusev1.TicketStatus_ReleaseExpired{}}},
			want:   vaultapi.ErrReleaseExpired,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			c := vaultfake.New(t, vaultfake.Handlers{Use: &vaultfake.Use{
				OnPollTicket: func(*vaultusev1.PollTicketRequest) (*vaultusev1.PollTicketResponse, error) {
					return pollStatus(tc.status), nil
				},
			}})

			_, err := vaultapi.AwaitCreate(context.Background(), c.VaultUse, "vault-1", ticketOutcome())
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}

			if tc.text != "" && !strings.Contains(err.Error(), tc.text) {
				t.Errorf("err %q does not carry the reason %q", err, tc.text)
			}
		})
	}
}

func TestAwaitCreate_RejectsEmptyOutcome(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{})

	_, err := vaultapi.AwaitCreate(context.Background(), c.VaultUse, "vault-1", &vaultusev1.CreateOutcome{})
	if err == nil {
		t.Fatal("expected an error for an outcome with neither result nor ticket")
	}
}

func TestAwaitDelete_InlineAndTicket(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Use: &vaultfake.Use{
		OnPollTicket: func(*vaultusev1.PollTicketRequest) (*vaultusev1.PollTicketResponse, error) {
			return &vaultusev1.PollTicketResponse{Outcome: &vaultusev1.TicketOutcome{
				Outcome: &vaultusev1.TicketOutcome_DeleteResult{DeleteResult: &vaultusev1.DeleteResult{}},
			}}, nil
		},
	}})

	inline := &vaultusev1.DeleteOutcome{Union: &vaultusev1.DeleteOutcome_Result{Result: &vaultusev1.DeleteResult{}}}

	err := vaultapi.AwaitDelete(context.Background(), c.VaultUse, "vault-1", inline)
	if err != nil {
		t.Fatalf("inline AwaitDelete: %v", err)
	}

	ticket := &vaultusev1.DeleteOutcome{Union: &vaultusev1.DeleteOutcome_Ticket{Ticket: &vaultusev1.Ticket{TicketId: []byte("t1")}}}

	err = vaultapi.AwaitDelete(context.Background(), c.VaultUse, "vault-1", ticket)
	if err != nil {
		t.Fatalf("ticket AwaitDelete: %v", err)
	}
}

func TestAwaitDelete_Denied(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Use: &vaultfake.Use{
		OnPollTicket: func(*vaultusev1.PollTicketRequest) (*vaultusev1.PollTicketResponse, error) {
			return pollStatus(&vaultusev1.TicketStatus{State: &vaultusev1.TicketStatus_Denied_{Denied: &vaultusev1.TicketStatus_Denied{Reason: "no"}}}), nil
		},
	}})

	ticket := &vaultusev1.DeleteOutcome{Union: &vaultusev1.DeleteOutcome_Ticket{Ticket: &vaultusev1.Ticket{TicketId: []byte("t1")}}}

	err := vaultapi.AwaitDelete(context.Background(), c.VaultUse, "vault-1", ticket)
	if !errors.Is(err, vaultapi.ErrDenied) {
		t.Fatalf("err = %v, want ErrDenied", err)
	}
}

var (
	errGone    = errors.New("gone")
	errRefused = errors.New("refused")
)

func serveRecord(t *testing.T, kind string, params proto.Message) *vaultfake.Browse {
	t.Helper()

	return &vaultfake.Browse{
		OnGetRecord: func(*vaultbrowsev1.GetRecordRequest) (*vaultbrowsev1.GetRecordResponse, error) {
			return vaultfake.Record(t, kind, nil, params), nil
		},
	}
}

func TestGetRecord_DecodesIdP(t *testing.T) {
	t.Parallel()

	idp := &saml2v3.IdPParams{X509Certificate: []byte("der"), ProviderId: "urn:idp", SsoUrl: "https://sso", IdpSerial: 4}
	c := vaultfake.New(t, vaultfake.Handlers{Browse: serveRecord(t, vaultapi.KindSAML2IDP, idp)})

	kind, params, revision, err := vaultapi.GetRecord(context.Background(), c.VaultBrowse, "vault-1", "idp")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}

	if kind != vaultapi.KindSAML2IDP || revision != 1 {
		t.Errorf("kind = %q, revision = %d", kind, revision)
	}

	got, err := vaultapi.DecodeIdP(params)
	if err != nil {
		t.Fatalf("DecodeIdP: %v", err)
	}

	if !proto.Equal(got, idp) {
		t.Errorf("idp = %v, want %v", got, idp)
	}
}

func TestGetRecord_DecodesOIDCIssuer(t *testing.T) {
	t.Parallel()

	issuer := &wifv2.WorkloadIdentityAuthorityState{
		Issuer:  "https://issuer",
		JwksUri: "https://issuer/jwks",
		Keys:    []*wifv2.PublishedKey{{Kid: "k1", PublicKey: &keysv1.SerializedKey{Data: []byte("pub")}}},
	}
	c := vaultfake.New(t, vaultfake.Handlers{Browse: serveRecord(t, vaultapi.KindWIFAuthority, issuer)})

	kind, params, _, err := vaultapi.GetRecord(context.Background(), c.VaultBrowse, "vault-1", "issuer")
	if err != nil {
		t.Fatalf("GetRecord: %v", err)
	}

	if kind != vaultapi.KindWIFAuthority {
		t.Errorf("kind = %q", kind)
	}

	got, err := vaultapi.DecodeOIDCIssuer(params)
	if err != nil {
		t.Fatalf("DecodeOIDCIssuer: %v", err)
	}

	if !proto.Equal(got, issuer) {
		t.Errorf("issuer = %v, want %v", got, issuer)
	}
}

func TestFetchRecord_NotFound(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnGetRecord: func(*vaultbrowsev1.GetRecordRequest) (*vaultbrowsev1.GetRecordResponse, error) {
			return nil, connect.NewError(connect.CodeNotFound, errGone)
		},
	}})

	_, err := vaultapi.FetchRecord(context.Background(), c.VaultBrowse, "vault-1", "missing")
	if !vaultapi.IsNotFound(err) {
		t.Fatalf("IsNotFound(%v) = false", err)
	}

	if vaultapi.IsNotFound(errGone) || vaultapi.IsNotFound(nil) {
		t.Error("IsNotFound matched an unrelated error")
	}
}

func TestSignatureSpec_RoundTrip(t *testing.T) {
	t.Parallel()

	for _, alg := range vaultapi.AlgValues() {
		spec, err := vaultapi.SignatureSpecFromAlg(alg)
		if err != nil {
			t.Fatalf("SignatureSpecFromAlg(%q): %v", alg, err)
		}

		if got := vaultapi.AlgFromSignatureSpec(spec); got != alg {
			t.Errorf("round trip %q = %q", alg, got)
		}
	}

	_, err := vaultapi.SignatureSpecFromAlg("HS256")
	if err == nil {
		t.Error("expected an error for an unsupported algorithm")
	}
}

func TestEnumMappings_RoundTrip(t *testing.T) {
	t.Parallel()

	for _, s := range vaultapi.NotificationPolicyValues() {
		if got := vaultapi.NotificationPolicyToString(vaultapi.NotificationPolicyFromString(s)); got != s {
			t.Errorf("notification policy %q round trips to %q", s, got)
		}
	}

	for _, s := range vaultapi.SensitivityValues() {
		if got := vaultapi.SensitivityToString(vaultapi.SensitivityFromString(s)); got != s {
			t.Errorf("sensitivity %q round trips to %q", s, got)
		}
	}

	if vaultapi.SensitivityFromString("") != nil {
		t.Error("empty sensitivity should map to nil")
	}
}

func TestWriteOptions_ParsesWait(t *testing.T) {
	t.Parallel()

	opts, err := vaultapi.WriteOptions("because", "90s")
	if err != nil {
		t.Fatalf("WriteOptions: %v", err)
	}

	if opts.GetJustification() != "because" || opts.GetWait().AsDuration().Seconds() != 90 {
		t.Errorf("opts = %v", opts)
	}

	_, err = vaultapi.WriteOptions("", "soon")
	if err == nil {
		t.Error("expected an error for an unparseable wait")
	}
}

// blockingPoll holds every poll open until release is closed. Close it before the fake server, which waits for open handlers.
func blockingPoll(polling chan<- struct{}, release <-chan struct{}) func(*vaultusev1.PollTicketRequest) (*vaultusev1.PollTicketResponse, error) {
	return func(*vaultusev1.PollTicketRequest) (*vaultusev1.PollTicketResponse, error) {
		polling <- struct{}{}
		<-release

		return &vaultusev1.PollTicketResponse{}, nil
	}
}

func awaitInterrupted(t *testing.T, c *client.Client, polling <-chan struct{}) error {
	t.Helper()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errs := make(chan error, 1)

	go func() {
		_, err := vaultapi.AwaitCreate(ctx, c.VaultUse, "vault-1", ticketOutcome())
		errs <- err
	}()

	<-polling
	cancel()

	return <-errs
}

func TestAwaitCreate_CancelsTicketWhenContextEnds(t *testing.T) {
	t.Parallel()

	polling := make(chan struct{}, 1)
	release := make(chan struct{})
	cancelled := make(chan *vaultusev1.CancelRequest, 1)

	c := vaultfake.New(t, vaultfake.Handlers{Use: &vaultfake.Use{
		OnPollTicket: blockingPoll(polling, release),
		OnCancel: func(req *vaultusev1.CancelRequest) (*vaultusev1.CancelResponse, error) {
			cancelled <- req

			return &vaultusev1.CancelResponse{}, nil
		},
	}})
	t.Cleanup(func() { close(release) })

	err := awaitInterrupted(t, c, polling)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}

	req := <-cancelled
	if req.GetBase().GetVaultId() != "vault-1" || string(req.GetBase().GetTicketId()) != "t1" || req.GetBase().GetReason() != "cancelled by the Terraform provider" {
		t.Errorf("cancel request = %v", req)
	}
}

func TestAwaitCreate_SurfacesCancelRefusal(t *testing.T) {
	t.Parallel()

	polling := make(chan struct{}, 1)
	release := make(chan struct{})

	c := vaultfake.New(t, vaultfake.Handlers{Use: &vaultfake.Use{
		OnPollTicket: blockingPoll(polling, release),
		OnCancel: func(*vaultusev1.CancelRequest) (*vaultusev1.CancelResponse, error) {
			return nil, connect.NewError(connect.CodePermissionDenied, errRefused)
		},
	}})
	t.Cleanup(func() { close(release) })

	err := awaitInterrupted(t, c, polling)
	if !errors.Is(err, context.Canceled) || !strings.Contains(err.Error(), "permission_denied") {
		t.Fatalf("err = %v, want both the cancellation and the refusal", err)
	}
}

func TestAwaitCreate_InlineResultSendsNoCancel(t *testing.T) {
	t.Parallel()

	cancels := 0

	c := vaultfake.New(t, vaultfake.Handlers{Use: &vaultfake.Use{
		OnCancel: func(*vaultusev1.CancelRequest) (*vaultusev1.CancelResponse, error) {
			cancels++

			return &vaultusev1.CancelResponse{}, nil
		},
	}})

	ctx, cancel := context.WithCancel(context.Background())
	cancel()

	outcome := &vaultusev1.CreateOutcome{Union: &vaultusev1.CreateOutcome_Result{Result: &vaultusev1.CreateResult{SecretId: "node-1"}}}

	_, err := vaultapi.AwaitCreate(ctx, c.VaultUse, "vault-1", outcome)
	if err != nil || cancels != 0 {
		t.Fatalf("err = %v, cancels = %d", err, cancels)
	}
}

func TestAwaitDelete_CancelsTicketWhenContextEnds(t *testing.T) {
	t.Parallel()

	polling := make(chan struct{}, 1)
	release := make(chan struct{})
	cancelled := make(chan struct{}, 1)

	c := vaultfake.New(t, vaultfake.Handlers{Use: &vaultfake.Use{
		OnPollTicket: blockingPoll(polling, release),
		OnCancel: func(*vaultusev1.CancelRequest) (*vaultusev1.CancelResponse, error) {
			cancelled <- struct{}{}

			return &vaultusev1.CancelResponse{}, nil
		},
	}})
	t.Cleanup(func() { close(release) })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	errs := make(chan error, 1)
	ticket := &vaultusev1.DeleteOutcome{Union: &vaultusev1.DeleteOutcome_Ticket{Ticket: &vaultusev1.Ticket{TicketId: []byte("t1")}}}

	go func() { errs <- vaultapi.AwaitDelete(ctx, c.VaultUse, "vault-1", ticket) }()

	<-polling
	cancel()

	err := <-errs
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("err = %v, want context.Canceled", err)
	}

	<-cancelled
}
