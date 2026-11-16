package connectedapp

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/proto"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	saml2v3 "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/saml2/v3"
	wifv2 "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/wif/v2"
	teamresourcev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/teamresource/v1"
	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	vaulttypesv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaulttypes/v1"
	catalog "github.com/splitsecure/terraform-provider-splitsecure/splitsecure/connectedapp"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi/vaultfake"
)

const (
	idpSerial   = 7
	authorityID = "authority-1"
)

// recordFromCreate stores a create as the enclave does: the fields in order, a value derived at creation as text,
// the layout, and the binding the server adds.
func recordFromCreate(create *pb.CreateAppParams) *pb.ConnectedAppParams {
	rec := &pb.ConnectedAppParams{Template: create.GetTemplate(), Title: create.GetTitle()}

	for _, f := range create.GetFields() {
		f = proto.CloneOf(f)
		if f.GetStringField().GetDerived() == pb.Derived_DERIVED_AT_CREATION_ID {
			f.Type = &pb.Field_StringField{StringField: &pb.StringField{Source: &pb.StringField_DerivedText{DerivedText: &pb.DerivedText{Value: derivedSubject}}}}
		}

		rec.Fields = append(rec.Fields, f)
	}

	if s := create.GetSaml2(); s != nil {
		rec.App = &pb.ConnectedAppParams_Saml2{Saml2: &pb.SAML2App{
			Binding: &pb.SAML2Binding{IdpSerial: idpSerial, SpMetadata: s.GetSpMetadata()},
			Layout:  s.GetLayout(),
		}}

		return rec
	}

	rec.App = &pb.ConnectedAppParams_Oidc{Oidc: &pb.OIDCApp{
		Binding: &pb.OIDCBinding{AuthorityId: authorityID, KeyId: create.GetOidc().GetKeyId()},
		Layout:  create.GetOidc().GetLayout(),
	}}

	return rec
}

// representativeModel sets every field of the template a create may set, plain fields first, then one instance of each repeatable field.
func representativeModel(t *testing.T, tmpl *catalog.Template) appModel {
	t.Helper()

	var plain, instances []fieldModel

	for i := range tmpl.Fields {
		s := &tmpl.Fields[i]
		if catalog.ImplicitField(s) != nil {
			continue
		}

		fm := representativeField(t, s)
		if s.Repeatable {
			fm.Key = types.StringValue("k-" + s.Name)
			instances = append(instances, fm)

			continue
		}

		plain = append(plain, fm)
	}

	m := model(t, tmpl.Name, append(plain, instances...)...)
	if tmpl.Protocol == catalog.ProtocolSAML2 {
		return withSAML2(t, m)
	}

	return withOIDC(t, m, "aw==")
}

func representativeField(t *testing.T, s *catalog.FieldSpec) fieldModel {
	t.Helper()

	return newField(t, s.Name, func(f *fieldModel) {
		switch s.Sources[0] {
		case catalog.SourceFixed:
			setFixed(t, f, s)
		case catalog.SourceModifiable:
			setModifiable(t, f, s)
		case catalog.SourceDerivedAtCreation:
			f.Derived = types.StringValue(derivedAtCreation)
		case catalog.SourceDerivedPerSignIn:
			f.Derived = types.StringValue(derivedPerSignIn)
		case catalog.SourceRequester:
			f.Requester = types.StringValue(map[string]string{"REQUESTER_EMAIL": requesterEmail}[s.Requesters[0]])
			if f.Requester.ValueString() == "" {
				f.Requester = types.StringValue(requesterSessionName)
			}
		}
	})
}

func setFixed(t *testing.T, f *fieldModel, s *catalog.FieldSpec) {
	t.Helper()

	switch s.Type {
	case catalog.TypeString:
		f.Value = types.StringValue("value-" + s.Name)
		if len(s.Choices) > 0 {
			f.Value = types.StringValue(s.Choices[0])
		}
	case catalog.TypeStringList:
		f.Values = stringList(cmpOr(s.Choices, []string{"a", "b"}))
	case catalog.TypeDuration:
		f.Seconds = types.Int64Value(max(s.MinSeconds, 60))
	case catalog.TypeJSONObject:
		f.JSON = types.StringValue(`{"b":1,"a":"x","c":{"z":true,"y":[1,"two"]}}`)
	}
}

func setModifiable(t *testing.T, f *fieldModel, s *catalog.FieldSpec) {
	t.Helper()

	choices := cmpOr(s.Choices, []string{"a", "b"})

	switch s.Type {
	case catalog.TypeStringList:
		f.Choices = stringList(choices)
		f.DefaultValues = stringList(choices[:1])
	case catalog.TypeDuration:
		lo := max(s.MinSeconds, 60)
		f.DurationRange = list(t, durationRangeType(), []durationRangeModel{{
			MinSeconds: types.Int64Value(lo), MaxSeconds: types.Int64Value(max(s.MaxSeconds, lo)), DefaultSeconds: types.Int64Value(lo),
		}})
	case catalog.TypeString, catalog.TypeJSONObject:
		f.Choices = stringList(choices)
		f.DefaultValue = types.StringValue(choices[0])
	}
}

func cmpOr(a, b []string) []string {
	if len(a) > 0 {
		return a
	}

	return b
}

func mustParams(t *testing.T, m *appModel) *pb.CreateAppParams {
	t.Helper()

	p, diags := params(context.Background(), m)
	if diags.HasError() {
		t.Fatalf("building the create: %v", diags)
	}

	return p
}

func assertListsEqual(t *testing.T, what string, got, want types.List) {
	t.Helper()

	if !got.Equal(want) {
		t.Errorf("%s:\n got  %v\n want %v", what, got, want)
	}
}

func TestEveryTemplateRoundTripsThroughARecord(t *testing.T) {
	t.Parallel()

	for _, name := range catalog.Names() {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			tmpl, err := catalog.Lookup(name)
			if err != nil {
				t.Fatal(err)
			}

			m := representativeModel(t, tmpl)
			rec := recordFromCreate(mustParams(t, &m))

			in, err := inputsFromRecord(context.Background(), tmpl, rec)
			if err != nil {
				t.Fatalf("rebuilding: %v", err)
			}

			assertListsEqual(t, "field", in.fields, m.Fields)
			assertListsEqual(t, "saml2", in.saml2, m.SAML2)
			assertListsEqual(t, "oidc", in.oidc, m.OIDC)
			assertListsEqual(t, "name_id", in.nameID, m.NameID)

			imported := m
			imported.SAML2, imported.OIDC, imported.Fields, imported.NameID = types.ListNull(saml2Type()), types.ListNull(oidcType()), types.ListNull(fieldType()), types.ListNull(nameIDType())

			err = importInputs(context.Background(), &imported, rec)
			if err != nil {
				t.Fatalf("importing: %v", err)
			}

			assertListsEqual(t, "imported field", imported.Fields, m.Fields)
		})
	}
}

func TestAffixRoundTrips(t *testing.T) {
	t.Parallel()

	claim := newField(t, "claim", func(f *fieldModel) {
		f.Key = types.StringValue("team")
		f.DefaultValue = types.StringValue("ops-core")
		f.Affix = list(t, affixType(), []affixModel{{Prefix: types.StringValue("ops-"), Suffix: types.StringNull(), MaxLength: types.Int64Value(32)}})
	})
	m := genericOIDCModel(t, claim)

	p := mustParams(t, &m)
	want := catalog.ModifiableString("claim_1", catalog.ModifiableStringOptions{Default: new("ops-core"), Affix: &catalog.Affix{Prefix: "ops-", MaxLength: 32}})
	want.Label = "Claim"

	if got := p.GetFields()[3]; !proto.Equal(got, want) {
		t.Errorf("built field = %v, want %v", got, want)
	}

	tmpl, _ := catalog.Lookup("oidc/generic")

	in, err := inputsFromRecord(context.Background(), tmpl, recordFromCreate(p))
	if err != nil {
		t.Fatal(err)
	}

	assertListsEqual(t, "field", in.fields, m.Fields)
}

func TestAffixRefusals(t *testing.T) {
	t.Parallel()

	affix := list(t, affixType(), []affixModel{{Prefix: types.StringValue("ops-"), Suffix: types.StringNull(), MaxLength: types.Int64Null()}})
	withChoices := newField(t, "claim", func(f *fieldModel) {
		f.Key = types.StringValue("team")
		f.Affix = affix
		f.Choices = stringList([]string{"ops-a"})
	})
	onList := newField(t, "claim_list", func(f *fieldModel) {
		f.Key = types.StringValue("teams")
		f.Affix = affix
	})

	for name, tt := range map[string]struct {
		field fieldModel
		want  error
	}{
		"choices and affix": {withChoices, errChoicesAndAffix},
		"affix on a list":   {onList, errListAffix},
	} {
		tmpl, _ := catalog.Lookup("oidc/generic")
		spec, _ := tmpl.Spec(tt.field.Name.ValueString())

		_, err := tt.field.field(context.Background(), spec)
		if !errors.Is(err, tt.want) {
			t.Errorf("%s: err = %v, want %v", name, err, tt.want)
		}
	}
}

// fakeNode is one node of a fake vault tree.
type fakeNode struct {
	id       string
	kind     string
	params   proto.Message
	children []fakeNode
	hidden   bool
}

// vaultBrowse serves the app as node-1, a tree of nodes listed one child per page, and the records in it.
func vaultBrowse(t *testing.T, app *pb.ConnectedAppParams, root []fakeNode) *vaultfake.Browse {
	t.Helper()

	nodes := map[string]fakeNode{}

	var index func([]fakeNode)
	index = func(ns []fakeNode) {
		for _, n := range ns {
			nodes[n.id] = n
			index(n.children)
		}
	}
	index(root)

	return &vaultfake.Browse{
		OnGetRecord: func(req *vaultbrowsev1.GetRecordRequest) (*vaultbrowsev1.GetRecordResponse, error) {
			attrs := &teamresourcev1.BaseResourceAttributes{Name: "aws-prod", NotificationPolicy: teamresourcev1.NotificationPolicy_NOTIFICATION_POLICY_NOTIFY_EVERYONE}
			if req.GetBase().GetNodeId() == "node-1" {
				return vaultfake.Record(t, kindConnectedApp, attrs, app), nil
			}

			n, ok := nodes[req.GetBase().GetNodeId()]
			if !ok || n.params == nil {
				return nil, connect.NewError(connect.CodeNotFound, errGone)
			}

			return vaultfake.Record(t, n.kind, attrs, n.params), nil
		},
		OnListNodes: func(req *vaultbrowsev1.ListNodesRequest) (*vaultbrowsev1.ListNodesResponse, error) {
			children := root

			if parent := req.GetBase().GetLocator().GetParentNodeId(); parent != "" {
				n, ok := nodes[parent]
				if !ok || n.hidden {
					return nil, connect.NewError(connect.CodeNotFound, errGone)
				}

				children = n.children
			}

			i, _ := strconv.Atoi(string(req.GetBase().GetPage().GetDirectionOrCursor().GetCursor()))
			if i >= len(children) {
				return &vaultbrowsev1.ListNodesResponse{}, nil
			}

			c := children[i]
			resp := &vaultbrowsev1.ListNodesResponse{Children: []*vaulttypesv1.Node{{
				NodeId: c.id, IsDir: c.kind == "", Record: &vaulttypesv1.RecordFacts{Kind: c.kind},
			}}}

			if i+1 < len(children) {
				resp.NextCursor = []byte(strconv.Itoa(i + 1))
			}

			return resp, nil
		},
	}
}

func idpNode(id string, serial uint64) fakeNode {
	return fakeNode{id: id, kind: vaultapi.KindSAML2IDP, params: &saml2v3.IdPParams{IdpSerial: serial}}
}

func issuerNode(id, authority string) fakeNode {
	return fakeNode{id: id, kind: vaultapi.KindWIFAuthority, params: &wifv2.WorkloadIdentityAuthorityState{AuthorityId: authority}}
}

func TestFindIssuer(t *testing.T) {
	t.Parallel()

	samlApp := recordFromCreate(samlAWSParams(t))
	oidcApp := recordFromCreate(mustParams(t, new(genericOIDCModel(t))))

	tests := map[string]struct {
		app  *pb.ConnectedAppParams
		root []fakeNode
		want string
	}{
		"SAML2 identity provider at the root": {samlApp, []fakeNode{idpNode("idp-other", 3), idpNode("idp-1", idpSerial)}, "idp-1"},
		"OIDC issuer in a subfolder": {oidcApp, []fakeNode{
			issuerNode("issuer-other", "authority-0"),
			{id: "folder-a", children: []fakeNode{{id: "folder-b", children: []fakeNode{issuerNode("issuer-1", authorityID)}}}},
		}, "issuer-1"},
		"a folder the caller cannot see is skipped": {samlApp, []fakeNode{
			{id: "folder-hidden", hidden: true}, {id: "folder-c", children: []fakeNode{idpNode("idp-2", idpSerial)}},
		}, "idp-2"},
		"another kind with the same serial is not the issuer": {samlApp, []fakeNode{issuerNode("issuer-2", authorityID)}, ""},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			c := newClient(t, nil, vaultBrowse(t, tt.app, tt.root))

			got, err := findIssuer(context.Background(), c.VaultBrowse, "vault-1", tt.app)
			if tt.want == "" {
				if !errors.Is(err, errIssuerNotFound) {
					t.Errorf("err = %v, want errIssuerNotFound", err)
				}

				return
			}

			if err != nil || got != tt.want {
				t.Errorf("findIssuer = %q, %v, want %q", got, err, tt.want)
			}
		})
	}
}

// importApp imports node-1 and reads it, as terraform import and the plan after it do.
func importApp(t *testing.T, app *pb.ConnectedAppParams, root []fakeNode) (appModel, error) {
	t.Helper()

	return importAs(t, "vault-1/node-1", vaultBrowse(t, app, root))
}

func importAs(t *testing.T, id string, browse *vaultfake.Browse) (appModel, error) {
	t.Helper()

	ctx := context.Background()
	r := &appResource{client: newClient(t, nil, browse)}

	importResp := &resource.ImportStateResponse{State: emptyState(t)}
	r.ImportState(ctx, resource.ImportStateRequest{ID: id}, importResp)

	if importResp.Diagnostics.HasError() {
		return appModel{}, errors.New(importResp.Diagnostics.Errors()[0].Detail()) //nolint:err113 // test surfaces the diagnostic.
	}

	readResp := &resource.ReadResponse{State: importResp.State}
	r.Read(ctx, resource.ReadRequest{State: importResp.State}, readResp)

	if readResp.Diagnostics.HasError() {
		return appModel{}, errors.New(readResp.Diagnostics.Errors()[0].Detail()) //nolint:err113 // test surfaces the diagnostic.
	}

	var got appModel

	if diags := readResp.State.Get(ctx, &got); diags.HasError() {
		t.Fatalf("reading state: %v", diags)
	}

	return got, nil
}

func TestImportIDNamesTheIssuer(t *testing.T) {
	t.Parallel()

	app := recordFromCreate(samlAWSParams(t))
	root := []fakeNode{idpNode("idp-other", 3), idpNode("idp-1", idpSerial)}

	browse := vaultBrowse(t, app, root)
	browse.OnListNodes = func(*vaultbrowsev1.ListNodesRequest) (*vaultbrowsev1.ListNodesResponse, error) {
		t.Error("an import id that names the issuer searched the vault")

		return &vaultbrowsev1.ListNodesResponse{}, nil
	}

	got, err := importAs(t, "vault-1/node-1/vault-1/idp-1", browse)
	if err != nil || got.IssuerID.ValueString() != "idp-1" || got.IssuerVaultID.ValueString() != "vault-1" {
		t.Errorf("issuer = %s/%s, err = %v, want vault-1/idp-1", got.IssuerVaultID, got.IssuerID, err)
	}

	_, err = importAs(t, "vault-1/node-1/vault-1/idp-other", browse)
	if err == nil || !strings.Contains(err.Error(), errNotTheIssuer.Error()) {
		t.Errorf("another issuer: err = %v, want errNotTheIssuer", err)
	}

	for _, id := range []string{"vault-1/node-1/vault-1", "vault-1//vault-1/idp-1", "vault-1"} {
		_, err := importAs(t, id, browse)
		if err == nil {
			t.Errorf("import id %q: no error", id)
		}
	}
}

func liveShapes(t *testing.T) map[string]appModel {
	t.Helper()

	gcp := withOIDC(t, model(t, "oidc/gcp",
		fixed(t, "project_number", "123456789012"), fixed(t, "pool_id", "splitsecure"), fixed(t, "provider_id", "splitsecure-oidc"),
		fixed(t, "service_account_email", "federated@demo.iam.gserviceaccount.com"),
		newField(t, "access_token_lifetime", func(f *fieldModel) {
			f.DurationRange = list(t, durationRangeType(), []durationRangeModel{{MinSeconds: types.Int64Value(300), MaxSeconds: types.Int64Value(3600), DefaultSeconds: types.Int64Value(3600)}})
		}),
	), "aw==")
	azure := withOIDC(t, model(t, "oidc/azure",
		fixed(t, "tenant_id", "4c61d01c-03f5-4a71-a93e-358e4ac22c4e"), fixed(t, "client_id", "0d6f1d6e-5b0a-4a51-9d2b-7d1e2c3f4a5b"),
		newField(t, "lifetime", func(f *fieldModel) {
			f.DurationRange = list(t, durationRangeType(), []durationRangeModel{{MinSeconds: types.Int64Value(300), MaxSeconds: types.Int64Value(3600), DefaultSeconds: types.Int64Value(600)}})
		}),
	), "aw==")
	awsOIDC := withOIDC(t, model(t, "oidc/aws",
		fixed(t, "role_arn", roleARN),
		newField(t, "session_duration", func(f *fieldModel) {
			f.DurationRange = list(t, durationRangeType(), []durationRangeModel{{MinSeconds: types.Int64Value(900), MaxSeconds: types.Int64Value(3600), DefaultSeconds: types.Int64Value(1800)}})
		}),
		newField(t, "session_tag", func(f *fieldModel) {
			f.Key = types.StringValue("Team")
			f.Value = types.StringValue("platform")
		}),
	), "aw==")

	return map[string]appModel{"saml2/aws": samlAWSModel(t), "oidc/aws": awsOIDC, "oidc/gcp": gcp, "oidc/azure": azure}
}

func TestConnectedAppImportsLiveShapes(t *testing.T) {
	t.Parallel()

	root := []fakeNode{{id: "folder-aws", children: []fakeNode{idpNode("idp-1", idpSerial), issuerNode("issuer-1", authorityID)}}}

	for name, m := range liveShapes(t) {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			got, err := importApp(t, recordFromCreate(mustParams(t, &m)), root)
			if err != nil {
				t.Fatalf("import: %v", err)
			}

			assertListsEqual(t, "field", got.Fields, m.Fields)
			assertListsEqual(t, "saml2", got.SAML2, m.SAML2)
			assertListsEqual(t, "oidc", got.OIDC, m.OIDC)
			assertListsEqual(t, "name_id", got.NameID, m.NameID)

			wantIssuer := map[bool]string{true: "idp-1", false: "issuer-1"}[len(m.SAML2.Elements()) > 0]
			if got.IssuerID.ValueString() != wantIssuer || got.Template.ValueString() != name {
				t.Errorf("issuer_id, template = %v, %v", got.IssuerID, got.Template)
			}

			got.IssuerID = m.IssuerID
			assertNoChange(t, &got, &m)
		})
	}
}

// assertNoChange plans the config against the state and requires no replacement.
func assertNoChange(t *testing.T, state, config *appModel) {
	t.Helper()

	resp := modifyPlan(t, state, config)

	if resp.Diagnostics.HasError() || len(resp.RequiresReplace) != 0 {
		t.Errorf("plan replaces %v, diags %v", resp.RequiresReplace, resp.Diagnostics)
	}
}

func modifyPlan(t *testing.T, state, config *appModel) *resource.ModifyPlanResponse {
	t.Helper()

	cfg := *config
	cfg.ID, cfg.VaultID, cfg.Title, cfg.DerivedValues = state.ID, state.VaultID, state.Title, state.DerivedValues
	cfg.Sensitivity, cfg.Name, cfg.FolderID = state.Sensitivity, state.Name, state.FolderID

	s := stateOf(t, state)
	p := stateOf(t, &cfg)
	plan := tfsdk.Plan{Schema: p.Schema, Raw: p.Raw}

	resp := &resource.ModifyPlanResponse{Plan: plan}
	(&appResource{}).ModifyPlan(context.Background(), resource.ModifyPlanRequest{Plan: plan, State: s, Config: tfsdk.Config{Schema: p.Schema, Raw: p.Raw}}, resp)

	return resp
}

func TestModifyPlanIgnoresFieldOrder(t *testing.T) {
	t.Parallel()

	state := samlAWSModel(t)

	var fields []fieldModel
	state.Fields.ElementsAs(context.Background(), &fields, false)
	slices.Reverse(fields)

	config := state
	config.Fields = list(t, fieldType(), fields)

	resp := modifyPlan(t, &state, &config)
	if len(resp.RequiresReplace) != 0 {
		t.Fatalf("reordering the field blocks replaces %v", resp.RequiresReplace)
	}

	var planned types.List

	resp.Plan.GetAttribute(context.Background(), pathField(), &planned)
	assertListsEqual(t, "planned field", planned, config.Fields)
}

func TestModifyPlanReplacesOnAChangedField(t *testing.T) {
	t.Parallel()

	state := samlAWSModel(t)
	config := samlAWSModel(t)

	var fields []fieldModel
	config.Fields.ElementsAs(context.Background(), &fields, false)
	fields[0].Value = types.StringValue("arn:aws:iam::123456789012:role/other")
	config.Fields = list(t, fieldType(), fields)

	resp := modifyPlan(t, &state, &config)
	if len(resp.RequiresReplace) != 1 || !resp.RequiresReplace[0].Equal(pathField()) {
		t.Errorf("requires replace = %v, want [field]", resp.RequiresReplace)
	}
}

func TestReadKeepsAnExplicitlySetImplicitField(t *testing.T) {
	t.Parallel()

	sessionName := newField(t, "role_session_name", func(f *fieldModel) { f.Requester = types.StringValue(requesterSessionName) })

	m := samlAWSModel(t)

	var fields []fieldModel
	m.Fields.ElementsAs(context.Background(), &fields, false)
	m.Fields = list(t, fieldType(), append(fields, sessionName))

	rec := recordFromCreate(mustParams(t, &m))

	err := inputsBuildRecord(context.Background(), &m, rec)
	if err != nil {
		t.Fatal(err)
	}

	imported, err := importApp(t, rec, []fakeNode{idpNode("idp-1", idpSerial)})
	if err != nil {
		t.Fatal(err)
	}

	assertListsEqual(t, "imported field without the implicit one", imported.Fields, samlAWSModel(t).Fields)
	imported.IssuerID = m.IssuerID
	assertNoChange(t, &imported, &m)
}

func TestReadRefusesWhatTheSchemaCannotExpress(t *testing.T) {
	t.Parallel()

	tests := map[string]struct {
		mutate func(*pb.ConnectedAppParams)
		cause  string
	}{
		"a requester constraint with a prefix": {func(rec *pb.ConnectedAppParams) {
			rec.Fields = append(rec.Fields, &pb.Field{Name: "requester_session_name", Type: &pb.Field_StringField{StringField: &pb.StringField{
				Source: &pb.StringField_Requester{Requester: &pb.RequesterSource{Kind: pb.Requester_REQUESTER_SESSION_NAME, Constraint: &pb.StringAffix{Prefix: "ops-"}}},
			}}})
		}, `field "requester_session_name": ` + errRequesterCut.Error()},
		"a field the template does not declare": {func(rec *pb.ConnectedAppParams) {
			rec.Fields = append(rec.Fields, catalog.FixedString("newer_field", "x"))
		}, `field "newer_field" is not a field of the saml2/aws template`},
		"a sub-second duration": {func(rec *pb.ConnectedAppParams) {
			f := catalog.FixedDuration("session_duration", 900)
			f.GetDurationField().GetFixed().GetValue().Nanos = 5
			rec.Fields[2] = f
		}, `field "session_duration": ` + errSubSecond.Error()},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			rec := recordFromCreate(samlAWSParams(t))
			tt.mutate(rec)

			_, err := importApp(t, rec, []fakeNode{idpNode("idp-1", idpSerial)})
			if err == nil || !strings.Contains(err.Error(), errUnexpressible.Error()) || !strings.Contains(err.Error(), tt.cause) {
				t.Fatalf("err = %v, want a refusal naming %q", err, tt.cause)
			}
		})
	}

	null := &pb.JsonObjectValue{Members: []*pb.JsonObjectValue_Member{{Name: "a", Value: &pb.JsonObjectValue_Value{Kind: &pb.JsonObjectValue_Value_NullValue{}}}}}

	fm := emptyFieldModel("claims")

	err := fm.setSource(&pb.Field{Type: &pb.Field_JsonObjectField{JsonObjectField: &pb.JsonObjectField{Source: &pb.JsonObjectField_Fixed{Fixed: null}}}})
	if !errors.Is(err, errJSONNull) {
		t.Errorf("a JSON null: err = %v, want errJSONNull", err)
	}
}

func TestReadWarnsAndKeepsInputsThatNoLongerBuildTheRecord(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	m := samlAWSModel(t)
	m.ID, m.VaultID = types.StringValue("node-1"), types.StringValue("vault-1")

	rec := recordFromCreate(mustParams(t, &m))
	rec.Fields = append(rec.Fields, catalog.FixedString("newer_field", "x"))

	r := &appResource{client: newClient(t, nil, vaultBrowse(t, rec, nil))}
	state := stateOf(t, &m)
	resp := &resource.ReadResponse{State: state}
	r.Read(ctx, resource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() || resp.Diagnostics.WarningsCount() != 1 {
		t.Fatalf("diagnostics = %v, want one warning", resp.Diagnostics)
	}

	var got appModel

	resp.State.Get(ctx, &got)
	assertListsEqual(t, "kept field", got.Fields, m.Fields)
}

func TestImportedMetadataXMLRoundTrips(t *testing.T) {
	t.Parallel()

	m := samlAWSModel(t)
	m.SAML2 = list(t, saml2Type(), []saml2Model{{EntityID: types.StringNull(), ACSURL: types.StringNull(), MetadataXML: types.StringValue(multiACSMetadata)}})

	got, err := importApp(t, recordFromCreate(mustParams(t, &m)), []fakeNode{idpNode("idp-1", idpSerial)})
	if err != nil {
		t.Fatal(err)
	}

	var blocks []saml2Model
	got.SAML2.ElementsAs(context.Background(), &blocks, false)

	if len(blocks) != 1 || blocks[0].MetadataXML.IsNull() || !blocks[0].EntityID.IsNull() {
		t.Fatalf("saml2 block = %v, want metadata_xml only", got.SAML2)
	}

	got.IssuerID = m.IssuerID
	assertNoChange(t, &got, &m)
}

func TestModifyPlanKeepsReformattedMetadataXML(t *testing.T) {
	t.Parallel()

	state := samlAWSModel(t)
	state.SAML2 = list(t, saml2Type(), []saml2Model{{EntityID: types.StringNull(), ACSURL: types.StringNull(), MetadataXML: types.StringValue(multiACSMetadata)}})

	config := state
	config.SAML2 = list(t, saml2Type(), []saml2Model{{EntityID: types.StringNull(), ACSURL: types.StringNull(), MetadataXML: types.StringValue(reformattedMultiACSMetadata)}})

	resp := modifyPlan(t, &state, &config)
	if len(resp.RequiresReplace) != 0 {
		t.Fatalf("reformatting metadata_xml replaces %v", resp.RequiresReplace)
	}
}
