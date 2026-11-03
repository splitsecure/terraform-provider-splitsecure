package oidc

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"google.golang.org/protobuf/types/known/timestamppb"

	wifv2 "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/wif/v2"
	issuancev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/issuance/v1"
	keysv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/keys/v1"
	teamresourcev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/teamresource/v1"
	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	vaultusev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi/vaultfake"
)

func issuerSchema(ctx context.Context, t *testing.T) rschema.Schema {
	t.Helper()

	resp := &resource.SchemaResponse{}
	NewIssuerResource().Schema(ctx, resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}

	return resp.Schema
}

var errGone = errors.New("gone")

func assertAttrs(t *testing.T, s rschema.Schema, names []string, kind string, ok func(rschema.Attribute) bool) {
	t.Helper()

	for _, name := range names {
		attr, found := s.Attributes[name]
		if !found || !ok(attr) {
			t.Errorf("attribute %q should be %s", name, kind)
		}
	}
}

func TestIssuerSchema_Attributes(t *testing.T) {
	t.Parallel()

	s := issuerSchema(context.Background(), t)

	assertAttrs(t, s, []string{"vault_id", "name"}, "Required", rschema.Attribute.IsRequired)
	assertAttrs(t, s, []string{"description", "notification_policy", "sensitivity", "algs", "allow_free_form_tokens", "justification", "wait"}, "Optional", rschema.Attribute.IsOptional)
	assertAttrs(t, s, []string{"id", "issuer", "jwks_url", "authority_id", "keys", "not_before", "not_after"}, "Computed only", func(a rschema.Attribute) bool {
		return a.IsComputed() && !a.IsOptional()
	})
	assertAttrs(t, s, []string{"justification", "wait"}, "WriteOnly", rschema.Attribute.IsWriteOnly)
}

func issuerPlan(ctx context.Context, t *testing.T) issuerModel {
	t.Helper()

	algs, diags := types.ListValueFrom(ctx, types.StringType, []string{vaultapi.AlgES256, vaultapi.AlgMLDSA65})
	if diags.HasError() {
		t.Fatalf("building algs: %v", diags)
	}

	unknown := types.StringUnknown()

	return issuerModel{
		ID:                 unknown,
		VaultID:            types.StringValue("vault-1"),
		Name:               types.StringValue("ci"),
		Description:        types.StringValue(""),
		NotificationPolicy: types.StringValue("notify_everyone"),
		ParentNodeID:       types.StringValue("folder-1"),
		Sensitivity:        unknown,
		Justification:      types.StringNull(),
		Wait:               types.StringNull(),
		Algs:               algs,
		AllowFreeForm:      types.BoolValue(true),
		Issuer:             unknown,
		JWKSURL:            unknown,
		AuthorityID:        unknown,
		Keys:               types.ListUnknown(issuerKeyType()),
		NotBefore:          unknown,
		NotAfter:           unknown,
	}
}

func issuerRecordHandler(t *testing.T) func(*vaultbrowsev1.GetRecordRequest) (*vaultbrowsev1.GetRecordResponse, error) {
	t.Helper()

	state := &wifv2.WorkloadIdentityAuthorityState{
		Issuer:      "https://issuer.example.com/a1",
		JwksUri:     "https://issuer.example.com/a1/jwks",
		AuthorityId: "a1",
		NotBefore:   timestamppb.New(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)),
		Keys: []*wifv2.PublishedKey{
			{Kid: "k1", PublicKey: &keysv1.SerializedKey{Data: []byte("pub1"), Spec: &keysv1.Spec{Union: &keysv1.Spec_Signature{
				Signature: &keysv1.SignatureSpec{Union: &keysv1.SignatureSpec_Ecdsa{Ecdsa: keysv1.ECDSA_ECDSA_NIST_P256}},
			}}}},
			{Kid: "k2", PublicKey: &keysv1.SerializedKey{Data: []byte("pub2")}},
		},
	}

	return func(req *vaultbrowsev1.GetRecordRequest) (*vaultbrowsev1.GetRecordResponse, error) {
		if req.GetBase().GetNodeId() != "node-1" {
			return nil, connect.NewError(connect.CodeNotFound, errGone)
		}

		attrs := &teamresourcev1.BaseResourceAttributes{
			Name:               "ci",
			NotificationPolicy: teamresourcev1.NotificationPolicy_NOTIFICATION_POLICY_NOTIFY_EVERYONE,
		}

		return vaultfake.Record(t, vaultapi.KindWIFAuthority, attrs, state, &issuancev1.MaterialBinding{Name: "k1", KeyId: []byte("bound-1")}), nil
	}
}

func issuerUse(viaTicket bool, created **vaultusev1.CreateWIFAuthorityRequest, deleted **vaultusev1.DeleteRequest) *vaultfake.Use {
	return &vaultfake.Use{
		OnCreateWIFAuthority: func(req *vaultusev1.CreateWIFAuthorityRequest) (*vaultusev1.CreateWIFAuthorityResponse, error) {
			*created = req

			return &vaultusev1.CreateWIFAuthorityResponse{Outcome: vaultfake.CreateOutcome(viaTicket, "node-1")}, nil
		},
		OnDelete: func(req *vaultusev1.DeleteRequest) (*vaultusev1.DeleteResponse, error) {
			*deleted = req

			return &vaultusev1.DeleteResponse{Outcome: vaultfake.DeleteOutcome(viaTicket)}, nil
		},
		OnPollTicket: func(*vaultusev1.PollTicketRequest) (*vaultusev1.PollTicketResponse, error) {
			return vaultfake.ResolvedTicket(*deleted != nil, "node-1"), nil
		},
	}
}

func createIssuer(ctx context.Context, t *testing.T, r *issuerResource) tfsdk.State {
	t.Helper()

	s := issuerSchema(ctx, t)
	empty := tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
	plan := tfsdk.Plan{Schema: s, Raw: empty.Raw}
	model := issuerPlan(ctx, t)

	if diags := plan.Set(ctx, &model); diags.HasError() {
		t.Fatalf("building plan: %v", diags)
	}

	cfgModel := issuerPlan(ctx, t)
	cfgModel.Justification = types.StringValue("because")
	cfgModel.Wait = types.StringValue("10s")
	cfgState := empty

	if diags := cfgState.Set(ctx, &cfgModel); diags.HasError() {
		t.Fatalf("building config: %v", diags)
	}

	resp := &resource.CreateResponse{State: empty}
	r.Create(ctx, resource.CreateRequest{Plan: plan, Config: tfsdk.Config{Schema: s, Raw: cfgState.Raw}}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Create: %v", resp.Diagnostics)
	}

	return resp.State
}

func TestIssuerLifecycle(t *testing.T) {
	t.Parallel()

	for name, viaTicket := range map[string]bool{"inline result": false, "ticket": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var (
				created *vaultusev1.CreateWIFAuthorityRequest
				deleted *vaultusev1.DeleteRequest
			)

			c := vaultfake.New(t, vaultfake.Handlers{
				Use:    issuerUse(viaTicket, &created, &deleted),
				Browse: &vaultfake.Browse{OnGetRecord: issuerRecordHandler(t)},
			})

			r := &issuerResource{client: c}
			ctx := context.Background()

			state := createIssuer(ctx, t, r)
			assertCreateRequest(t, created)

			var got issuerModel

			if diags := state.Get(ctx, &got); diags.HasError() {
				t.Fatalf("reading state: %v", diags)
			}

			assertIssuerState(t, &got)
			assertIssuerKeys(ctx, t, &got)

			readResp := &resource.ReadResponse{State: state}
			r.Read(ctx, resource.ReadRequest{State: state}, readResp)

			if readResp.Diagnostics.HasError() || readResp.State.Raw.IsNull() {
				t.Fatalf("Read: %v", readResp.Diagnostics)
			}

			deleteResp := &resource.DeleteResponse{State: state}
			r.Delete(ctx, resource.DeleteRequest{State: state}, deleteResp)

			if deleteResp.Diagnostics.HasError() {
				t.Fatalf("Delete: %v", deleteResp.Diagnostics)
			}

			if deleted.GetBase().GetSecretId() != "node-1" || deleted.GetBase().GetVaultId() != "vault-1" {
				t.Errorf("delete request = %v", deleted)
			}
		})
	}
}

func assertCreateRequest(t *testing.T, req *vaultusev1.CreateWIFAuthorityRequest) {
	t.Helper()

	base := req.GetBase()

	if base.GetVaultId() != "vault-1" || base.GetCommon().GetName() != "ci" || base.GetCommon().GetRequestedParentNodeId() != "folder-1" || !base.GetAllowFreeFormTokens() {
		t.Errorf("create request = %v", req)
	}

	if base.GetOptions().GetJustification() != "because" || base.GetOptions().GetWait().AsDuration() != 10*time.Second {
		t.Errorf("write options = %v", base.GetOptions())
	}

	algs := make([]string, 0, len(base.GetAlgs()))
	for _, spec := range base.GetAlgs() {
		algs = append(algs, vaultapi.AlgFromSignatureSpec(spec))
	}

	if !slices.Equal(algs, []string{vaultapi.AlgES256, vaultapi.AlgMLDSA65}) {
		t.Errorf("algs = %v", algs)
	}
}

func assertIssuerState(t *testing.T, got *issuerModel) {
	t.Helper()

	if got.ID.ValueString() != "node-1" || got.Issuer.ValueString() != "https://issuer.example.com/a1" || got.AuthorityID.ValueString() != "a1" {
		t.Errorf("state = %+v", got)
	}

	if got.NotBefore.ValueString() != "2026-01-02T03:04:05Z" || !got.NotAfter.IsNull() {
		t.Errorf("validity = %v .. %v", got.NotBefore, got.NotAfter)
	}
}

// assertIssuerKeys checks that k1 carries its bound key id and k2 falls back to the published key bytes.
func assertIssuerKeys(ctx context.Context, t *testing.T, got *issuerModel) {
	t.Helper()

	var keys []issuerKeyModel

	if diags := got.Keys.ElementsAs(ctx, &keys, false); diags.HasError() || len(keys) != 2 {
		t.Fatalf("keys = %v, diags = %v", keys, diags)
	}

	if keys[0].Kid.ValueString() != "k1" || keys[0].Alg.ValueString() != vaultapi.AlgES256 || keys[0].KeyID.ValueString() != "Ym91bmQtMQ==" {
		t.Errorf("key 0 = %+v", keys[0])
	}

	if keys[1].KeyID.ValueString() != "cHViMg==" {
		t.Errorf("key 1 = %+v", keys[1])
	}
}

func TestIssuerRead_RemovesGoneRecord(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnGetRecord: func(*vaultbrowsev1.GetRecordRequest) (*vaultbrowsev1.GetRecordResponse, error) {
			return nil, connect.NewError(connect.CodeNotFound, errGone)
		},
	}})

	ctx := context.Background()
	s := issuerSchema(ctx, t)
	state := tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}

	model := issuerPlan(ctx, t)
	model.ID = types.StringValue("node-1")

	for _, f := range []*types.String{&model.Sensitivity, &model.Issuer, &model.JWKSURL, &model.AuthorityID, &model.NotBefore, &model.NotAfter} {
		*f = types.StringValue("x")
	}

	model.Keys = types.ListNull(issuerKeyType())

	if diags := state.Set(ctx, &model); diags.HasError() {
		t.Fatalf("building state: %v", diags)
	}

	resp := &resource.ReadResponse{State: state}
	(&issuerResource{client: c}).Read(ctx, resource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
		t.Errorf("state should be removed when the record is gone; diags = %v", resp.Diagnostics)
	}
}
