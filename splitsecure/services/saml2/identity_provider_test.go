package saml2

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	teamresourcev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/teamresource/v1"
	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	vaultusev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi/vaultfake"
)

func idpPlan() saml2IdentityProviderModel {
	unknown := types.StringUnknown()

	return saml2IdentityProviderModel{
		ID:                    unknown,
		VaultID:               types.StringValue("vault-1"),
		Name:                  types.StringValue("aws"),
		Description:           types.StringValue(""),
		NotBefore:             unknown,
		NotAfter:              unknown,
		NotificationPolicy:    types.StringValue("notify_everyone"),
		Folder:                types.ListValueMust(types.StringType, []attr.Value{types.StringValue("terraform"), types.StringValue("prod")}),
		Sensitivity:           unknown,
		Justification:         types.StringNull(),
		Wait:                  types.StringNull(),
		ProviderID:            unknown,
		SSOURLRedirect:        unknown,
		SSOURLPost:            unknown,
		MetadataXML:           unknown,
		SigningCertificatePEM: unknown,
		SigningCertificateDER: unknown,
		SigningPublicKeyPEM:   unknown,
		SigningPublicKeyDER:   unknown,
		IDPSerial:             unknown,
	}
}

func idpConfig(ctx context.Context, t *testing.T, s tfsdk.State) tfsdk.Config {
	t.Helper()

	cfg := idpPlan()
	cfg.Justification = types.StringValue("because")
	cfg.Wait = types.StringValue("30s")

	if diags := s.Set(ctx, &cfg); diags.HasError() {
		t.Fatalf("building config: %v", diags)
	}

	return tfsdk.Config{Schema: s.Schema, Raw: s.Raw}
}

func emptyState(ctx context.Context, t *testing.T, r resource.Resource) tfsdk.State {
	t.Helper()

	s := schemaForResource(ctx, t, r)

	return tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(ctx), nil)}
}

func idpRecordHandler(t *testing.T) func(*vaultbrowsev1.GetRecordRequest) (*vaultbrowsev1.GetRecordResponse, error) {
	t.Helper()

	params := freshIDPParams(t)

	return func(req *vaultbrowsev1.GetRecordRequest) (*vaultbrowsev1.GetRecordResponse, error) {
		if req.GetBase().GetNodeId() != "node-1" {
			return nil, connect.NewError(connect.CodeNotFound, errGone)
		}

		attrs := &teamresourcev1.BaseResourceAttributes{
			Name:               "aws",
			NotificationPolicy: teamresourcev1.NotificationPolicy_NOTIFICATION_POLICY_NOTIFY_EVERYONE,
		}

		return vaultfake.Record(t, "saml2-idp", attrs, params), nil
	}
}

func idpUse(viaTicket bool, created **vaultusev1.CreateSAML2IDPRequest, deleted **vaultusev1.DeleteRequest) *vaultfake.Use {
	return &vaultfake.Use{
		OnCreateSAML2IDP: func(req *vaultusev1.CreateSAML2IDPRequest) (*vaultusev1.CreateSAML2IDPResponse, error) {
			*created = req

			return &vaultusev1.CreateSAML2IDPResponse{Outcome: vaultfake.CreateOutcome(viaTicket, "node-1")}, nil
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

func TestIDPLifecycle(t *testing.T) {
	t.Parallel()

	for name, viaTicket := range map[string]bool{"inline result": false, "ticket": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var (
				created *vaultusev1.CreateSAML2IDPRequest
				deleted *vaultusev1.DeleteRequest
			)

			browse := &vaultfake.Browse{OnGetRecord: idpRecordHandler(t)}
			tree := &vaultfake.FolderTree{Existing: map[string]string{"terraform": "id-terraform"}}
			tree.Attach(browse)

			c := vaultfake.New(t, vaultfake.Handlers{
				Use:    idpUse(viaTicket, &created, &deleted),
				Browse: browse,
			})

			r := &saml2IdentityProvider{client: c}
			ctx := context.Background()

			state := createIDP(ctx, t, r)
			assertIDPCreateRequest(t, created)

			if !slices.Equal(tree.Created(), []string{"prod"}) || !slices.Equal(tree.Parents(), []string{"id-terraform"}) {
				t.Errorf("folders created %v under %v, want prod under the existing terraform folder", tree.Created(), tree.Parents())
			}

			var got saml2IdentityProviderModel

			if diags := state.Get(ctx, &got); diags.HasError() {
				t.Fatalf("reading created state: %v", diags)
			}

			assertIDPState(t, &got)

			readResp := &resource.ReadResponse{State: state}
			r.Read(ctx, resource.ReadRequest{State: state}, readResp)

			if readResp.Diagnostics.HasError() {
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

func assertIDPCreateRequest(t *testing.T, req *vaultusev1.CreateSAML2IDPRequest) {
	t.Helper()

	base := req.GetBase()

	if base.GetVaultId() != "vault-1" || base.GetCommon().GetName() != "aws" || base.GetCommon().GetRequestedParentNodeId() != "new-prod" {
		t.Errorf("create request = %v", req)
	}

	if base.GetOptions().GetJustification() != "because" || base.GetOptions().GetWait().AsDuration() != 30*time.Second {
		t.Errorf("write options = %v", base.GetOptions())
	}
}

func assertIDPState(t *testing.T, got *saml2IdentityProviderModel) {
	t.Helper()

	if got.ID.ValueString() != "node-1" || got.ProviderID.ValueString() != "https://idp.example.com/saml/idp/test" {
		t.Errorf("state = %+v", got)
	}

	if !strings.Contains(got.MetadataXML.ValueString(), "EntityDescriptor") || got.SigningCertificatePEM.ValueString() == "" {
		t.Errorf("metadata or certificate not populated: %+v", got)
	}

	if got.NotBefore.IsUnknown() || got.NotAfter.IsUnknown() || got.Sensitivity.IsUnknown() {
		t.Errorf("unknown values left in state: %+v", got)
	}
}

func createIDP(ctx context.Context, t *testing.T, r *saml2IdentityProvider) tfsdk.State {
	t.Helper()

	state := emptyState(ctx, t, r)

	plan := tfsdk.Plan{Schema: state.Schema, Raw: state.Raw}
	model := idpPlan()

	if diags := plan.Set(ctx, &model); diags.HasError() {
		t.Fatalf("building plan: %v", diags)
	}

	resp := &resource.CreateResponse{State: state}
	r.Create(ctx, resource.CreateRequest{Plan: plan, Config: idpConfig(ctx, t, emptyState(ctx, t, r))}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Create: %v", resp.Diagnostics)
	}

	return resp.State
}

func TestIDPRead_RemovesGoneRecord(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Browse: &vaultfake.Browse{
		OnGetRecord: func(*vaultbrowsev1.GetRecordRequest) (*vaultbrowsev1.GetRecordResponse, error) {
			return nil, connect.NewError(connect.CodeNotFound, errGone)
		},
	}})

	r := &saml2IdentityProvider{client: c}
	ctx := context.Background()

	state := emptyState(ctx, t, r)
	model := idpPlan()
	model.ID = types.StringValue("node-1")
	model.Name = types.StringValue("aws")

	for _, f := range []*types.String{
		&model.NotBefore, &model.NotAfter, &model.Sensitivity, &model.ProviderID, &model.SSOURLRedirect, &model.SSOURLPost,
		&model.MetadataXML, &model.SigningCertificatePEM, &model.SigningCertificateDER, &model.SigningPublicKeyPEM,
		&model.SigningPublicKeyDER, &model.IDPSerial,
	} {
		*f = types.StringValue("x")
	}

	if diags := state.Set(ctx, &model); diags.HasError() {
		t.Fatalf("building state: %v", diags)
	}

	resp := &resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("Read: %v", resp.Diagnostics)
	}

	if !resp.State.Raw.IsNull() {
		t.Error("state should be removed when the record is gone")
	}
}

var errGone = errors.New("gone")

type placementHarness struct {
	r     *saml2IdentityProvider
	tree  *vaultfake.FolderTree
	moves []*vaultbrowsev1.MoveNodeRequest
	opens int
	state tfsdk.State
}

// newPlacementHarness creates an IdP in terraform/prod, then counts every create, delete and move after that.
func newPlacementHarness(ctx context.Context, t *testing.T) *placementHarness {
	t.Helper()

	h := &placementHarness{tree: &vaultfake.FolderTree{Existing: map[string]string{"terraform": "id-terraform"}}}

	var (
		created *vaultusev1.CreateSAML2IDPRequest
		deleted *vaultusev1.DeleteRequest
	)

	use := idpUse(false, &created, &deleted)
	create := use.OnCreateSAML2IDP
	use.OnCreateSAML2IDP = func(req *vaultusev1.CreateSAML2IDPRequest) (*vaultusev1.CreateSAML2IDPResponse, error) {
		h.opens++

		return create(req)
	}
	del := use.OnDelete
	use.OnDelete = func(req *vaultusev1.DeleteRequest) (*vaultusev1.DeleteResponse, error) {
		h.opens++

		return del(req)
	}

	browse := &vaultfake.Browse{OnGetRecord: idpRecordHandler(t)}
	h.tree.Attach(browse)
	browse.OnMoveNode = func(req *vaultbrowsev1.MoveNodeRequest) (*vaultbrowsev1.MoveNodeResponse, error) {
		h.moves = append(h.moves, req)

		return &vaultbrowsev1.MoveNodeResponse{}, nil
	}

	h.r = &saml2IdentityProvider{client: vaultfake.New(t, vaultfake.Handlers{Use: use, Browse: browse})}
	h.state = createIDP(ctx, t, h.r)
	h.opens = 0

	return h
}

// update plans the state's model with mutate applied and runs Update.
func (h *placementHarness) update(ctx context.Context, t *testing.T, mutate func(*saml2IdentityProviderModel)) {
	t.Helper()

	var model saml2IdentityProviderModel

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

func TestIDPUpdate_MovesRecordToFolderIDInPlace(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newPlacementHarness(ctx, t)

	h.update(ctx, t, func(m *saml2IdentityProviderModel) {
		m.Folder = types.ListNull(types.StringType)
		m.FolderID = types.StringValue("f-new")
	})

	if len(h.moves) != 1 || h.moves[0].GetBase().GetNodeId() != "node-1" || h.moves[0].GetBase().GetVaultId() != "vault-1" || h.moves[0].GetBase().GetLocator().GetParentNodeId() != "f-new" {
		t.Errorf("moves = %v", h.moves)
	}

	if h.opens != 0 {
		t.Errorf("update created or deleted a record %d times", h.opens)
	}

	var got saml2IdentityProviderModel

	h.state.Get(ctx, &got)

	if got.FolderID.ValueString() != "f-new" || got.ID.ValueString() != "node-1" {
		t.Errorf("state = %+v", got)
	}
}

func TestIDPUpdate_CreatesMissingPathThenMoves(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newPlacementHarness(ctx, t)

	h.update(ctx, t, func(m *saml2IdentityProviderModel) {
		m.Folder = types.ListValueMust(types.StringType, []attr.Value{types.StringValue("terraform"), types.StringValue("staging")})
	})

	if !slices.Equal(h.tree.Created(), []string{"prod", "staging"}) || len(h.moves) != 1 || h.moves[0].GetBase().GetLocator().GetParentNodeId() != "new-staging" {
		t.Errorf("created = %v, moves = %v", h.tree.Created(), h.moves)
	}
}

func TestIDPUpdate_MovesBackToRootWithUnsetLocator(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newPlacementHarness(ctx, t)

	h.update(ctx, t, func(m *saml2IdentityProviderModel) {
		m.Folder = types.ListNull(types.StringType)
		m.FolderID = types.StringNull()
	})

	if len(h.moves) != 1 || h.moves[0].GetBase().GetLocator() != nil {
		t.Errorf("moves = %v, want one move with an unset locator", h.moves)
	}
}

func TestIDPUpdate_RefusesAChangeBeyondPlacement(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	h := newPlacementHarness(ctx, t)

	var model saml2IdentityProviderModel

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
