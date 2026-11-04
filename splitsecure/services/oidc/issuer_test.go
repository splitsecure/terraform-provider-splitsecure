package oidc

import (
	"context"
	"errors"
	"slices"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/attr"
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
		Folder:             types.ListValueMust(types.StringType, []attr.Value{types.StringValue("terraform"), types.StringValue("prod")}),
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

	// As a real record: published keys carry a JWK thumbprint kid, in an order of their own.
	state := &wifv2.WorkloadIdentityAuthorityState{
		Issuer:      "https://issuer.example.com/a1",
		JwksUri:     "https://issuer.example.com/a1/jwks",
		AuthorityId: "a1",
		NotBefore:   timestamppb.New(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)),
		Keys: []*wifv2.PublishedKey{
			{Kid: "thumb-eddsa", PublicKey: &keysv1.SerializedKey{Data: []byte("pub-eddsa"), Spec: signatureSpec(t, vaultapi.AlgEdDSA)}},
			{Kid: "thumb-es256", PublicKey: &keysv1.SerializedKey{Data: []byte("pub-es256"), Spec: signatureSpec(t, vaultapi.AlgES256)}},
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

		return vaultfake.Record(t, vaultapi.KindWIFAuthority, attrs, state, issuerMaterials(t)...), nil
	}
}

// issuerMaterials are the record's signing-key bindings, each named by its JWS alg; the ML-DSA-65 one has no published key.
func issuerMaterials(t *testing.T) []*issuancev1.MaterialBinding {
	t.Helper()

	binding := func(alg, publicKey string, keyID ...byte) *issuancev1.MaterialBinding {
		return &issuancev1.MaterialBinding{
			Name:  alg,
			KeyId: keyID,
			Form: &issuancev1.MaterialForm{Form: &issuancev1.MaterialForm_PrivateKey{PrivateKey: &issuancev1.PrivateKeyMaterial{
				Spec: signatureSpec(t, alg), PublicKey: []byte(publicKey),
			}}},
		}
	}

	return []*issuancev1.MaterialBinding{
		binding(vaultapi.AlgES256, "pub-es256", 1, 2, 3, 4),
		binding(vaultapi.AlgEdDSA, "pub-eddsa", 10, 11, 12, 13),
		binding(vaultapi.AlgMLDSA65, "pub-mldsa65", 5, 6, 7, 8),
	}
}

func signatureSpec(t *testing.T, alg string) *keysv1.Spec {
	t.Helper()

	sig, err := vaultapi.SignatureSpecFromAlg(alg)
	if err != nil {
		t.Fatal(err)
	}

	return &keysv1.Spec{Union: &keysv1.Spec_Signature{Signature: sig}}
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

			browse := &vaultfake.Browse{OnGetRecord: issuerRecordHandler(t)}
			tree := &vaultfake.FolderTree{Existing: map[string]string{"terraform": "id-terraform"}}
			tree.Attach(browse)

			c := vaultfake.New(t, vaultfake.Handlers{
				Use:    issuerUse(viaTicket, &created, &deleted),
				Browse: browse,
			})

			r := &issuerResource{client: c}
			ctx := context.Background()

			state := createIssuer(ctx, t, r)
			assertCreateRequest(t, created)

			if !slices.Equal(tree.Created(), []string{"prod"}) || !slices.Equal(tree.Parents(), []string{"id-terraform"}) {
				t.Errorf("folders created %v under %v, want prod under the existing terraform folder", tree.Created(), tree.Parents())
			}

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

	if base.GetVaultId() != "vault-1" || base.GetCommon().GetName() != "ci" || base.GetCommon().GetRequestedParentNodeId() != "new-prod" || !base.GetAllowFreeFormTokens() {
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

// assertIssuerKeys checks one key per binding, in binding order, each with its bound key id and the kid of the published key
// holding its public key, or a null kid when none does.
func assertIssuerKeys(ctx context.Context, t *testing.T, got *issuerModel) {
	t.Helper()

	var keys []issuerKeyModel

	if diags := got.Keys.ElementsAs(ctx, &keys, false); diags.HasError() {
		t.Fatalf("keys = %v, diags = %v", keys, diags)
	}

	want := []issuerKeyModel{
		{Kid: types.StringValue("thumb-es256"), Alg: types.StringValue(vaultapi.AlgES256), KeyID: types.StringValue("AQIDBA==")},
		{Kid: types.StringValue("thumb-eddsa"), Alg: types.StringValue(vaultapi.AlgEdDSA), KeyID: types.StringValue("CgsMDQ==")},
		{Kid: types.StringNull(), Alg: types.StringValue(vaultapi.AlgMLDSA65), KeyID: types.StringValue("BQYHCA==")},
	}

	if !slices.EqualFunc(keys, want, func(a, b issuerKeyModel) bool {
		return a.Kid.Equal(b.Kid) && a.Alg.Equal(b.Alg) && a.KeyID.Equal(b.KeyID)
	}) {
		t.Errorf("keys = %+v, want %+v", keys, want)
	}
}

func TestKeyModelsTakesAlgFromThePublishedKeyWhenTheBindingIsUnnamed(t *testing.T) {
	t.Parallel()

	authority := &wifv2.WorkloadIdentityAuthorityState{Keys: []*wifv2.PublishedKey{
		{Kid: "thumb-es384", PublicKey: &keysv1.SerializedKey{Data: []byte("pub-es384"), Spec: signatureSpec(t, vaultapi.AlgES384)}},
	}}
	material := &issuancev1.MaterialBinding{KeyId: []byte{9, 9, 9, 9}, Form: &issuancev1.MaterialForm{Form: &issuancev1.MaterialForm_PrivateKey{
		PrivateKey: &issuancev1.PrivateKeyMaterial{PublicKey: []byte("pub-es384")},
	}}}

	keys := keyModels(authority, &vaultapi.Record{Materials: []*issuancev1.MaterialBinding{material}})

	if len(keys) != 1 || keys[0].Alg.ValueString() != vaultapi.AlgES384 || keys[0].Kid.ValueString() != "thumb-es384" {
		t.Errorf("keys = %+v", keys)
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

type placementHarness struct {
	r     *issuerResource
	tree  *vaultfake.FolderTree
	moves []*vaultbrowsev1.MoveNodeRequest
	opens int
	state tfsdk.State
}

// newPlacementHarness creates an issuer in terraform/prod, then counts every create, delete and move after that.
func newPlacementHarness(ctx context.Context, t *testing.T) *placementHarness {
	t.Helper()

	h := &placementHarness{tree: &vaultfake.FolderTree{Existing: map[string]string{"terraform": "id-terraform"}}}

	var (
		created *vaultusev1.CreateWIFAuthorityRequest
		deleted *vaultusev1.DeleteRequest
	)

	use := issuerUse(false, &created, &deleted)
	create := use.OnCreateWIFAuthority
	use.OnCreateWIFAuthority = func(req *vaultusev1.CreateWIFAuthorityRequest) (*vaultusev1.CreateWIFAuthorityResponse, error) {
		h.opens++

		return create(req)
	}
	del := use.OnDelete
	use.OnDelete = func(req *vaultusev1.DeleteRequest) (*vaultusev1.DeleteResponse, error) {
		h.opens++

		return del(req)
	}

	browse := &vaultfake.Browse{OnGetRecord: issuerRecordHandler(t)}
	h.tree.Attach(browse)
	browse.OnMoveNode = func(req *vaultbrowsev1.MoveNodeRequest) (*vaultbrowsev1.MoveNodeResponse, error) {
		h.moves = append(h.moves, req)

		return &vaultbrowsev1.MoveNodeResponse{}, nil
	}

	h.r = &issuerResource{client: vaultfake.New(t, vaultfake.Handlers{Use: use, Browse: browse})}
	h.state = createIssuer(ctx, t, h.r)
	h.opens = 0

	return h
}

// update plans the state's model with mutate applied and runs Update.
func (h *placementHarness) update(ctx context.Context, t *testing.T, mutate func(*issuerModel)) {
	t.Helper()

	var model issuerModel

	if diags := h.state.Get(ctx, &model); diags.HasError() {
		t.Fatalf("reading state: %v", diags)
	}

	mutate(&model)

	plan := tfsdk.Plan{Schema: h.state.Schema, Raw: h.state.Raw}
	if diags := plan.Set(ctx, &model); diags.HasError() {
		t.Fatalf("building plan: %v", diags)
	}

	resp := &resource.UpdateResponse{State: h.state}
	h.r.Update(ctx, resource.UpdateRequest{Plan: plan, State: h.state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Update: %v", resp.Diagnostics)
	}

	h.state = resp.State
}

func TestIssuerUpdate_MovesRecordToFolderIDInPlace(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newPlacementHarness(ctx, t)

	h.update(ctx, t, func(m *issuerModel) {
		m.Folder = types.ListNull(types.StringType)
		m.FolderID = types.StringValue("f-new")
	})

	if len(h.moves) != 1 || h.moves[0].GetBase().GetNodeId() != "node-1" || h.moves[0].GetBase().GetVaultId() != "vault-1" || h.moves[0].GetBase().GetLocator().GetParentNodeId() != "f-new" {
		t.Errorf("moves = %v", h.moves)
	}

	if h.opens != 0 {
		t.Errorf("update created or deleted a record %d times", h.opens)
	}

	var got issuerModel

	h.state.Get(ctx, &got)

	if got.FolderID.ValueString() != "f-new" || got.ID.ValueString() != "node-1" {
		t.Errorf("state = %+v", got)
	}
}

func TestIssuerUpdate_CreatesMissingPathThenMoves(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newPlacementHarness(ctx, t)

	h.update(ctx, t, func(m *issuerModel) {
		m.Folder = types.ListValueMust(types.StringType, []attr.Value{types.StringValue("terraform"), types.StringValue("staging")})
	})

	if !slices.Equal(h.tree.Created(), []string{"prod", "staging"}) || len(h.moves) != 1 || h.moves[0].GetBase().GetLocator().GetParentNodeId() != "new-staging" {
		t.Errorf("created = %v, moves = %v", h.tree.Created(), h.moves)
	}
}

func TestIssuerUpdate_MovesBackToRootWithUnsetLocator(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newPlacementHarness(ctx, t)

	h.update(ctx, t, func(m *issuerModel) {
		m.Folder = types.ListNull(types.StringType)
		m.FolderID = types.StringNull()
	})

	if len(h.moves) != 1 || h.moves[0].GetBase().GetLocator() != nil {
		t.Errorf("moves = %v, want one move with an unset locator", h.moves)
	}
}

func TestIssuerUpdate_RefusesAChangeBeyondPlacement(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newPlacementHarness(ctx, t)

	var model issuerModel

	h.state.Get(ctx, &model)

	model.Name = types.StringValue("renamed")

	plan := tfsdk.Plan{Schema: h.state.Schema, Raw: h.state.Raw}
	plan.Set(ctx, &model)

	resp := &resource.UpdateResponse{State: h.state}
	h.r.Update(ctx, resource.UpdateRequest{Plan: plan, State: h.state}, resp)

	if !resp.Diagnostics.HasError() || len(h.moves) != 0 {
		t.Errorf("a name change should be refused; moves = %v", h.moves)
	}
}

// read refreshes the harness state and returns the model it ends with.
func (h *placementHarness) read(ctx context.Context, t *testing.T) issuerModel {
	t.Helper()

	resp := &resource.ReadResponse{State: h.state}
	h.r.Read(ctx, resource.ReadRequest{State: h.state}, resp)

	if resp.Diagnostics.HasError() || resp.State.Raw.IsNull() {
		t.Fatalf("Read: %v", resp.Diagnostics)
	}

	h.state = resp.State

	var got issuerModel

	h.state.Get(ctx, &got)

	return got
}

func TestIssuerRead_ReportsARecordMovedToAnotherFolderPath(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newPlacementHarness(ctx, t)
	h.tree.Nodes = map[string][]string{"node-1": {"terraform", "other", "aws"}}

	got := h.read(ctx, t)

	var path []string

	got.Folder.ElementsAs(ctx, &path, false)

	if !slices.Equal(path, []string{"terraform", "other"}) {
		t.Fatalf("folder = %v, want the observed path", path)
	}

	// The drift plans a move back to the configured path.
	h.update(ctx, t, func(m *issuerModel) {
		m.Folder = types.ListValueMust(types.StringType, []attr.Value{types.StringValue("terraform"), types.StringValue("prod")})
	})

	if len(h.moves) != 1 || h.moves[0].GetBase().GetNodeId() != "node-1" {
		t.Errorf("moves = %v", h.moves)
	}
}

func TestIssuerRead_ReportsARecordMovedFromItsFolderID(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newPlacementHarness(ctx, t)
	h.tree.Existing["a/b"] = "f-other"
	h.tree.Nodes = map[string][]string{"node-1": {"a", "b", "aws"}}

	h.update(ctx, t, func(m *issuerModel) {
		m.Folder = types.ListNull(types.StringType)
		m.FolderID = types.StringValue("f-conf")
	})

	got := h.read(ctx, t)

	if got.FolderID.ValueString() != "f-other" {
		t.Errorf("folder_id = %q, want the observed parent", got.FolderID.ValueString())
	}
}

func TestIssuerRead_KeepsStateWhenThePathIsTruncated(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newPlacementHarness(ctx, t)
	h.tree.Truncated = true
	h.tree.Nodes = map[string][]string{"node-1": {"elsewhere", "aws"}}

	before := h.state.Raw

	h.read(ctx, t)

	if !h.state.Raw.Equal(before) {
		t.Error("a truncated path must leave folder and folder_id as they were")
	}
}

func TestIssuerRead_ShowsNoDriftForARecordAtTheConfiguredPlace(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newPlacementHarness(ctx, t)
	h.tree.Nodes = map[string][]string{"node-1": {"terraform", "prod", "aws"}}

	before := h.state.Raw

	h.read(ctx, t)

	if !h.state.Raw.Equal(before) {
		t.Error("a record at the configured place must not drift")
	}
}
