package connectedapp

import (
	"context"
	"encoding/base64"
	"errors"
	"slices"
	"testing"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	teamresourcev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/teamresource/v1"
	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	vaultusev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
	catalog "github.com/splitsecure/terraform-provider-splitsecure/splitsecure/connectedapp"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi/vaultfake"
)

const (
	roleARN     = "arn:aws:iam::123456789012:role/ops"
	providerARN = "arn:aws:iam::123456789012:saml-provider/SplitSecure"
	emailFormat = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	entityID    = "urn:amazon:webservices"
	acsURL      = "https://signin.aws.amazon.com/saml"
)

var errGone = errors.New("gone")

func newClient(t *testing.T, use *vaultfake.Use, browse *vaultfake.Browse) *client.Client {
	t.Helper()

	return vaultfake.New(t, vaultfake.Handlers{Use: use, Browse: browse})
}

func appSchema(t *testing.T) rschema.Schema {
	t.Helper()

	resp := &resource.SchemaResponse{}
	NewConnectedAppResource().Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}

	return resp.Schema
}

func list[T any](t *testing.T, elem attr.Type, items []T) types.List {
	t.Helper()

	if items == nil {
		items = []T{}
	}

	l, diags := types.ListValueFrom(context.Background(), elem, items)
	if diags.HasError() {
		t.Fatalf("building list: %v", diags)
	}

	return l
}

// newField returns a field entry with every source unset, then applies set.
func newField(t *testing.T, name string, set func(*fieldModel)) fieldModel {
	t.Helper()

	null := types.StringNull()
	f := fieldModel{
		Name: types.StringValue(name), Key: null, Value: null, Values: types.ListNull(types.StringType),
		Seconds: types.Int64Null(), DurationRange: list[durationRangeModel](t, durationRangeType(), nil),
		Choices: types.ListNull(types.StringType), DefaultValue: null, Requester: null, Suffix: null, Derived: null, JSON: null,
	}
	set(&f)

	return f
}

func fixed(t *testing.T, name, value string) fieldModel {
	t.Helper()

	return newField(t, name, func(f *fieldModel) { f.Value = types.StringValue(value) })
}

func model(t *testing.T, template string, fields ...fieldModel) appModel {
	t.Helper()

	unknown := types.StringUnknown()
	null := types.StringNull()

	return appModel{
		ID: unknown, VaultID: unknown, Title: unknown, Sensitivity: unknown,
		IssuerVaultID:      types.StringValue("vault-1"),
		IssuerID:           types.StringValue("issuer-1"),
		Template:           types.StringValue(template),
		Name:               types.StringValue("aws-prod"),
		Description:        types.StringValue(""),
		NotificationPolicy: types.StringValue(vaultapi.NotificationPolicyNotifyEveryone),
		ParentNodeID:       null, Justification: null, Wait: null,
		SAML2:  list[saml2Model](t, saml2Type(), nil),
		OIDC:   list[oidcModel](t, oidcType(), nil),
		Fields: list(t, fieldType(), fields),
		NameID: list[nameIDModel](t, nameIDType(), nil),
	}
}

func withSAML2(t *testing.T, m appModel) appModel {
	t.Helper()

	m.SAML2 = list(t, saml2Type(), []saml2Model{{EntityID: types.StringValue(entityID), ACSURL: types.StringValue(acsURL)}})

	return m
}

func withOIDC(t *testing.T, m appModel, keyID string) appModel {
	t.Helper()

	m.OIDC = list(t, oidcType(), []oidcModel{{KeyID: types.StringValue(keyID)}})

	return m
}

func samlAWSModel(t *testing.T) appModel {
	t.Helper()

	durationRange := newField(t, "session_duration", func(f *fieldModel) {
		f.DurationRange = list(t, durationRangeType(), []durationRangeModel{{
			MinSeconds: types.Int64Value(900), MaxSeconds: types.Int64Value(3600), DefaultSeconds: types.Int64Value(1800),
		}})
	})
	team := newField(t, "session_tag", func(f *fieldModel) {
		f.Key = types.StringValue("Team")
		f.Value = types.StringValue("platform")
	})
	email := newField(t, "session_tag", func(f *fieldModel) {
		f.Key = types.StringValue("Email")
		f.Requester = types.StringValue(requesterEmail)
	})

	requester := newField(t, "requester_email", func(f *fieldModel) { f.Requester = types.StringValue(requesterEmail) })

	m := withSAML2(t, model(t, "saml2/aws",
		fixed(t, "role_arn", roleARN), fixed(t, "saml_provider_arn", providerARN), durationRange,
		fixed(t, "name_id_format", emailFormat), requester, team, email))
	m.NameID = list(t, nameIDType(), []nameIDModel{{Parts: list(t, types.StringType, []string{"field:requester_email"})}})

	return m
}

func samlAWSParams(t *testing.T) *pb.CreateAppParams {
	t.Helper()

	want, err := catalog.Build("saml2/aws", catalog.Binding{SAML2: catalog.MinimalSPMetadata(entityID, acsURL)},
		[]*pb.Field{
			catalog.FixedString("role_arn", roleARN),
			catalog.FixedString("saml_provider_arn", providerARN),
			catalog.DurationRange("session_duration", 900, 3600, new(int64(1800))),
			catalog.FixedString("name_id_format", emailFormat),
			catalog.RequesterString("requester_email", pb.Requester_REQUESTER_EMAIL, ""),
		},
		[]catalog.Instance{
			{Key: "Team", Field: catalog.FixedString("session_tag", "platform")},
			{Key: "Email", Field: catalog.RequesterString("session_tag", pb.Requester_REQUESTER_EMAIL, "")},
		},
		catalog.WithNameID(catalog.FieldPart("requester_email")))
	if err != nil {
		t.Fatal(err)
	}

	return want
}

func emptyState(t *testing.T) tfsdk.State {
	t.Helper()

	s := appSchema(t)

	return tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(context.Background()), nil)}
}

func stateOf(t *testing.T, m *appModel) tfsdk.State {
	t.Helper()

	st := emptyState(t)

	if diags := st.Set(context.Background(), m); diags.HasError() {
		t.Fatalf("building state: %v", diags)
	}

	return st
}

func configOf(t *testing.T, m *appModel) tfsdk.Config {
	t.Helper()

	st := stateOf(t, m)

	return tfsdk.Config{Schema: st.Schema, Raw: st.Raw}
}

func create(t *testing.T, r *appResource, m appModel) (tfsdk.State, error) {
	t.Helper()

	cfg := m
	cfg.Justification = types.StringValue("because")
	cfg.Wait = types.StringValue("10s")

	plan := stateOf(t, &m)
	resp := &resource.CreateResponse{State: emptyState(t)}
	r.Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan{Schema: plan.Schema, Raw: plan.Raw}, Config: configOf(t, &cfg)}, resp)

	if resp.Diagnostics.HasError() {
		return resp.State, errors.New(resp.Diagnostics.Errors()[0].Detail()) //nolint:err113 // test surfaces the diagnostic.
	}

	return resp.State, nil
}

func recordHandler(t *testing.T, app *pb.ConnectedAppParams) func(*vaultbrowsev1.GetRecordRequest) (*vaultbrowsev1.GetRecordResponse, error) {
	t.Helper()

	return func(req *vaultbrowsev1.GetRecordRequest) (*vaultbrowsev1.GetRecordResponse, error) {
		if req.GetBase().GetNodeId() != "node-1" || req.GetBase().GetVaultId() != "vault-1" {
			return nil, connect.NewError(connect.CodeNotFound, errGone)
		}

		attrs := &teamresourcev1.BaseResourceAttributes{
			Name:               "aws-prod",
			NotificationPolicy: teamresourcev1.NotificationPolicy_NOTIFICATION_POLICY_NOTIFY_EVERYONE,
		}

		return vaultfake.Record(t, kindConnectedApp, attrs, app), nil
	}
}

func samlRecord() *pb.ConnectedAppParams {
	return &pb.ConnectedAppParams{
		Template: "saml2/aws",
		Title:    "AWS (SAML)",
		App: &pb.ConnectedAppParams_Saml2{Saml2: &pb.SAML2App{
			Binding: &pb.SAML2Binding{IdpSerial: 7, SpMetadata: catalog.MinimalSPMetadata(entityID, acsURL)},
		}},
	}
}

func assertProtoEqual(t *testing.T, got, want proto.Message) {
	t.Helper()

	if !proto.Equal(got, want) {
		t.Errorf("messages differ\ngot:\n%s\nwant:\n%s", prototext.Format(got), prototext.Format(want))
	}
}

func TestConnectedAppSchema(t *testing.T) {
	t.Parallel()

	s := appSchema(t)

	for _, name := range []string{"issuer_vault_id", "issuer_id", "template", "name"} {
		if !s.Attributes[name].IsRequired() {
			t.Errorf("attribute %q should be required", name)
		}
	}

	for _, name := range []string{"id", "vault_id", "title"} {
		if a := s.Attributes[name]; !a.IsComputed() || a.IsOptional() {
			t.Errorf("attribute %q should be computed only", name)
		}
	}

	for _, name := range []string{"justification", "wait"} {
		if !s.Attributes[name].IsWriteOnly() {
			t.Errorf("attribute %q should be write-only", name)
		}
	}

	for _, name := range []string{"saml2", "oidc", "field", "name_id"} {
		if _, ok := s.Blocks[name].(rschema.ListNestedBlock); !ok {
			t.Errorf("block %q should be a list block", name)
		}
	}
}

func TestConnectedAppCreatesSAML2AWS(t *testing.T) {
	t.Parallel()

	for name, viaTicket := range map[string]bool{"inline result": false, "ticket": true} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			var (
				created *vaultusev1.CreateConnectedAppRequest
				deleted *vaultusev1.DeleteRequest
			)

			use := &vaultfake.Use{
				OnCreateConnectedApp: func(req *vaultusev1.CreateConnectedAppRequest) (*vaultusev1.CreateConnectedAppResponse, error) {
					created = req

					return &vaultusev1.CreateConnectedAppResponse{Outcome: vaultfake.CreateOutcome(viaTicket, "node-1")}, nil
				},
				OnDelete: func(req *vaultusev1.DeleteRequest) (*vaultusev1.DeleteResponse, error) {
					deleted = req

					return &vaultusev1.DeleteResponse{Outcome: vaultfake.DeleteOutcome(viaTicket)}, nil
				},
				OnPollTicket: func(*vaultusev1.PollTicketRequest) (*vaultusev1.PollTicketResponse, error) {
					return vaultfake.ResolvedTicket(deleted != nil, "node-1"), nil
				},
			}
			r := &appResource{client: newClient(t, use, &vaultfake.Browse{OnGetRecord: recordHandler(t, samlRecord())})}

			state, err := create(t, r, samlAWSModel(t))
			if err != nil {
				t.Fatalf("Create: %v", err)
			}

			assertProtoEqual(t, created.GetBase(), &vaultusev1.CreateConnectedAppRequest_Base{
				VaultId:  "vault-1",
				IssuerId: "issuer-1",
				Common: &vaultusev1.CreateCommon{
					Name:               "aws-prod",
					NotificationPolicy: teamresourcev1.NotificationPolicy_NOTIFICATION_POLICY_NOTIFY_EVERYONE,
				},
				App:     samlAWSParams(t),
				Options: &vaultusev1.WriteOptions{Justification: "because", Wait: durationpb.New(10e9)},
			})
			assertCreatedState(t, state, "AWS (SAML)")
			readAndDelete(t, r, state)

			if deleted.GetBase().GetSecretId() != "node-1" || deleted.GetBase().GetVaultId() != "vault-1" {
				t.Errorf("delete request = %v", deleted)
			}
		})
	}
}

func assertCreatedState(t *testing.T, state tfsdk.State, title string) {
	t.Helper()

	var got appModel

	if diags := state.Get(context.Background(), &got); diags.HasError() {
		t.Fatalf("reading state: %v", diags)
	}

	if got.ID.ValueString() != "node-1" || got.VaultID.ValueString() != "vault-1" || got.Title.ValueString() != title {
		t.Errorf("id, vault_id, title = %v, %v, %v", got.ID, got.VaultID, got.Title)
	}

	if len(got.Fields.Elements()) == 0 {
		t.Error("configured fields were not kept in state")
	}
}

func readAndDelete(t *testing.T, r *appResource, state tfsdk.State) {
	t.Helper()

	ctx := context.Background()
	readResp := &resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, readResp)

	if readResp.Diagnostics.HasError() || readResp.State.Raw.IsNull() || !readResp.State.Raw.Equal(state.Raw) {
		t.Fatalf("Read changed state or reported %v", readResp.Diagnostics)
	}

	deleteResp := &resource.DeleteResponse{State: state}
	r.Delete(ctx, resource.DeleteRequest{State: state}, deleteResp)

	if deleteResp.Diagnostics.HasError() {
		t.Fatalf("Delete: %v", deleteResp.Diagnostics)
	}
}

func TestConnectedAppCreatesOIDCAWS(t *testing.T) {
	t.Parallel()

	keyID := []byte("issuer-key-1")
	tag := newField(t, "session_tag", func(f *fieldModel) {
		f.Key = types.StringValue("Email")
		f.Requester = types.StringValue(requesterEmail)
		f.Suffix = types.StringValue("@corp.example")
	})
	seconds := newField(t, "session_duration", func(f *fieldModel) { f.Seconds = types.Int64Value(3600) })
	m := withOIDC(t, model(t, "oidc/aws", fixed(t, "role_arn", roleARN), seconds, tag), base64.StdEncoding.EncodeToString(keyID))

	var created *vaultusev1.CreateConnectedAppRequest

	use := &vaultfake.Use{OnCreateConnectedApp: func(req *vaultusev1.CreateConnectedAppRequest) (*vaultusev1.CreateConnectedAppResponse, error) {
		created = req

		return &vaultusev1.CreateConnectedAppResponse{Outcome: vaultfake.CreateOutcome(false, "node-1")}, nil
	}}
	record := &pb.ConnectedAppParams{Template: "oidc/aws", Title: "AWS (OIDC)", App: &pb.ConnectedAppParams_Oidc{Oidc: &pb.OIDCApp{
		Binding: &pb.OIDCBinding{KeyId: keyID},
	}}}
	r := &appResource{client: newClient(t, use, &vaultfake.Browse{OnGetRecord: recordHandler(t, record)})}

	state, err := create(t, r, m)
	if err != nil {
		t.Fatalf("Create: %v", err)
	}

	want, err := catalog.Build("oidc/aws", catalog.Binding{OIDCKeyID: keyID},
		[]*pb.Field{catalog.FixedString("role_arn", roleARN), catalog.FixedDuration("session_duration", 3600)},
		[]catalog.Instance{{Key: "Email", Field: catalog.RequesterString("session_tag", pb.Requester_REQUESTER_EMAIL, "@corp.example")}})
	if err != nil {
		t.Fatal(err)
	}

	assertProtoEqual(t, created.GetBase().GetApp(), want)
	assertCreatedState(t, state, "AWS (OIDC)")
}

func TestConnectedAppReadRemovesGoneRecord(t *testing.T) {
	t.Parallel()

	r := &appResource{client: newClient(t, nil, &vaultfake.Browse{
		OnGetRecord: func(*vaultbrowsev1.GetRecordRequest) (*vaultbrowsev1.GetRecordResponse, error) {
			return nil, connect.NewError(connect.CodeNotFound, errGone)
		},
	})}

	m := samlAWSModel(t)
	m.ID = types.StringValue("node-1")
	m.VaultID = types.StringValue("vault-1")
	m.Title = types.StringValue("AWS (SAML)")
	m.Sensitivity = types.StringValue("")
	state := stateOf(t, &m)

	resp := &resource.ReadResponse{State: state}
	r.Read(context.Background(), resource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
		t.Errorf("state should be removed when the record is gone; diags = %v", resp.Diagnostics)
	}
}

func validate(t *testing.T, m appModel) []string {
	t.Helper()

	// A config holds null, not unknown, where only the provider sets a value.
	m.ID, m.VaultID, m.Title, m.Sensitivity = types.StringNull(), types.StringNull(), types.StringNull(), types.StringNull()

	resp := &resource.ValidateConfigResponse{}
	(&appResource{}).ValidateConfig(context.Background(), resource.ValidateConfigRequest{Config: configOf(t, &m)}, resp)

	out := make([]string, 0, len(resp.Diagnostics.Errors()))
	for _, d := range resp.Diagnostics.Errors() {
		out = append(out, d.Summary())
	}

	return out
}

func TestConnectedAppRefusesBothOrNeitherBinding(t *testing.T) {
	t.Parallel()

	neither := model(t, "saml2/aws")
	both := withOIDC(t, withSAML2(t, model(t, "saml2/aws")), base64.StdEncoding.EncodeToString([]byte("k")))

	unknownIssuer := both
	unknownIssuer.IssuerID = types.StringUnknown()

	for name, m := range map[string]appModel{"neither": neither, "both": both, "both with an unknown issuer": unknownIssuer} {
		if got := validate(t, m); !slices.Equal(got, []string{"Invalid binding"}) {
			t.Errorf("%s: diagnostics = %v", name, got)
		}
	}

	created := false
	use := &vaultfake.Use{OnCreateConnectedApp: func(*vaultusev1.CreateConnectedAppRequest) (*vaultusev1.CreateConnectedAppResponse, error) {
		created = true

		return &vaultusev1.CreateConnectedAppResponse{}, nil
	}}

	_, err := create(t, &appResource{client: newClient(t, use, &vaultfake.Browse{})}, both)
	if err == nil || created {
		t.Errorf("Create with both blocks: err = %v, request sent = %v", err, created)
	}
}

func TestConnectedAppRefusesBadJSONField(t *testing.T) {
	t.Parallel()

	for _, raw := range []string{"not json", "[1]", `{"tier": 1.5}`, `{"none": null}`, `{"a": 1} {"b": 2}`} {
		claims := newField(t, "claims", func(f *fieldModel) { f.JSON = types.StringValue(raw) })
		m := withOIDC(t, model(t, "oidc/generic", fixed(t, "audience", "https://api.example.com"), fixed(t, "subject", "bot"),
			newField(t, "lifetime", func(f *fieldModel) { f.Seconds = types.Int64Value(600) }), claims), "aw==")

		if got := validate(t, m); !slices.Equal(got, []string{"Invalid field claims"}) {
			t.Errorf("json %q: diagnostics = %v", raw, got)
		}
	}
}

func TestConnectedAppAcceptsJSONField(t *testing.T) {
	t.Parallel()

	claims := newField(t, "claims", func(f *fieldModel) { f.JSON = types.StringValue(`{"tier": 2, "team": "platform"}`) })
	m := withOIDC(t, model(t, "oidc/generic", fixed(t, "audience", "https://api.example.com"), fixed(t, "subject", "bot"),
		newField(t, "lifetime", func(f *fieldModel) { f.Seconds = types.Int64Value(600) }), claims), "aw==")

	if got := validate(t, m); len(got) != 0 {
		t.Errorf("diagnostics = %v", got)
	}
}

func TestConnectedAppRefusesFieldShapes(t *testing.T) {
	t.Parallel()

	tests := map[string]fieldModel{
		"no source": newField(t, "role_arn", func(*fieldModel) {}),
		"two sources": newField(t, "role_arn", func(f *fieldModel) {
			f.Value = types.StringValue(roleARN)
			f.Seconds = types.Int64Value(60)
		}),
		"suffix without requester": newField(t, "role_arn", func(f *fieldModel) {
			f.Value = types.StringValue(roleARN)
			f.Suffix = types.StringValue("@corp.example")
		}),
	}

	for name, f := range tests {
		m := withSAML2(t, model(t, "saml2/aws", f))

		if got := validate(t, m); !slices.Equal(got, []string{"Invalid field role_arn"}) {
			t.Errorf("%s: diagnostics = %v", name, got)
		}
	}
}

func TestConnectedAppReportsTemplateErrorsAtPlan(t *testing.T) {
	t.Parallel()

	m := withSAML2(t, model(t, "saml2/aws", fixed(t, "role_arn", roleARN)))

	if got := validate(t, m); !slices.Equal(got, []string{"Invalid connected app"}) {
		t.Errorf("diagnostics = %v", got)
	}

	if got := validate(t, samlAWSModel(t)); len(got) != 0 {
		t.Errorf("valid config: diagnostics = %v", got)
	}

	noNameID := samlAWSModel(t)
	noNameID.NameID = list[nameIDModel](t, nameIDType(), nil)

	if got := validate(t, noNameID); !slices.Equal(got, []string{"Invalid connected app"}) {
		t.Errorf("config without a NameID: diagnostics = %v", got)
	}

	unknownRole := newField(t, "role_arn", func(f *fieldModel) { f.Value = types.StringUnknown() })
	if got := validate(t, withSAML2(t, model(t, "saml2/aws", unknownRole))); len(got) != 0 {
		t.Errorf("config with an unknown value should wait for apply; diagnostics = %v", got)
	}
}

func TestModifiableFieldTakesTemplateChoices(t *testing.T) {
	t.Parallel()

	f := newField(t, "role", func(f *fieldModel) { f.DefaultValue = types.StringValue("observer") })

	got, err := f.field(context.Background(), &catalog.FieldSpec{Name: "role", Choices: []string{"admin", "observer"}})
	if err != nil {
		t.Fatal(err)
	}

	assertProtoEqual(t, got, catalog.ModifiableString("role", catalog.ModifiableStringOptions{
		Default: new("observer"), Choices: []string{"admin", "observer"},
	}))

	_, err = f.field(context.Background(), &catalog.FieldSpec{Name: "role"})
	if !errors.Is(err, errNoChoices) {
		t.Errorf("without choices: err = %v, want errNoChoices", err)
	}
}

func TestConnectedAppImportRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	r := &appResource{client: newClient(t, nil, &vaultfake.Browse{OnGetRecord: recordHandler(t, samlRecord())})}

	importResp := &resource.ImportStateResponse{State: emptyState(t)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "vault-1/node-1"}, importResp)

	if importResp.Diagnostics.HasError() {
		t.Fatalf("ImportState: %v", importResp.Diagnostics)
	}

	readResp := &resource.ReadResponse{State: importResp.State}
	r.Read(ctx, resource.ReadRequest{State: importResp.State}, readResp)

	if readResp.Diagnostics.HasError() {
		t.Fatalf("Read: %v", readResp.Diagnostics)
	}

	assertImportedState(t, readResp.State)

	bad := &resource.ImportStateResponse{State: emptyState(t)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: "node-1"}, bad)

	if !bad.Diagnostics.HasError() {
		t.Error("an import id without a vault should be refused")
	}
}

func assertImportedState(t *testing.T, state tfsdk.State) {
	t.Helper()

	var got appModel

	if diags := state.Get(context.Background(), &got); diags.HasError() {
		t.Fatalf("reading state: %v", diags)
	}

	var saml2 []saml2Model

	if diags := got.SAML2.ElementsAs(context.Background(), &saml2, false); diags.HasError() || len(saml2) != 1 {
		t.Fatalf("saml2 block = %v, diags = %v", got.SAML2, diags)
	}

	for attrName, pair := range map[string][2]types.String{
		"id":              {got.ID, types.StringValue("node-1")},
		"vault_id":        {got.VaultID, types.StringValue("vault-1")},
		"issuer_vault_id": {got.IssuerVaultID, types.StringValue("vault-1")},
		"template":        {got.Template, types.StringValue("saml2/aws")},
		"title":           {got.Title, types.StringValue("AWS (SAML)")},
		"name":            {got.Name, types.StringValue("aws-prod")},
		"entity_id":       {saml2[0].EntityID, types.StringValue(entityID)},
		"acs_url":         {saml2[0].ACSURL, types.StringValue(acsURL)},
	} {
		if !pair[0].Equal(pair[1]) {
			t.Errorf("%s = %v, want %v", attrName, pair[0], pair[1])
		}
	}

	if len(got.OIDC.Elements()) != 0 {
		t.Errorf("oidc block = %v, want none", got.OIDC)
	}
}
