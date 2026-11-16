package connectedapp

import (
	"errors"
	"slices"
	"strings"
	"testing"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	samlv2 "github.com/splitsecure/apis/gen/go/proto/splitsecure/oasis/saml/v2"
	"google.golang.org/protobuf/encoding/prototext"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/durationpb"
	"google.golang.org/protobuf/types/known/emptypb"
)

const (
	roleARN        = "arn:aws:iam::123456789012:role/ops"
	providerARN    = "arn:aws:iam::123456789012:saml-provider/S"
	emailFormat    = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
	awsTags        = "https://aws.amazon.com/tags"
	principalTags  = "principal_tags"
	principalTagAt = "https://aws.amazon.com/SAML/Attributes/PrincipalTag:"
)

func ref(name string) *pb.ExprPart {
	return &pb.ExprPart{Part: &pb.ExprPart_Field{Field: &pb.FieldRef{Name: name}}}
}

func text(s string) *pb.ExprPart {
	return &pb.ExprPart{Part: &pb.ExprPart_Text{Text: s}}
}

func expr(parts ...*pb.ExprPart) *pb.Expr {
	return &pb.Expr{Parts: parts}
}

func secs(n int64) *durationpb.Duration {
	return &durationpb.Duration{Seconds: n}
}

func pbFixed(name, label, value string) *pb.Field {
	return &pb.Field{Name: name, Label: label, Type: &pb.Field_StringField{StringField: &pb.StringField{
		Source: &pb.StringField_Fixed{Fixed: &pb.StringValue{Value: value}},
	}}}
}

func pbDerived(name, label string, d pb.Derived) *pb.Field {
	return &pb.Field{Name: name, Label: label, Type: &pb.Field_StringField{StringField: &pb.StringField{
		Source: &pb.StringField_Derived{Derived: d},
	}}}
}

func pbRequester(name, label string, kind pb.Requester, constraint *pb.StringAffix) *pb.Field {
	return &pb.Field{Name: name, Label: label, Type: &pb.Field_StringField{StringField: &pb.StringField{
		Source: &pb.StringField_Requester{Requester: &pb.RequesterSource{Kind: kind, Constraint: constraint}},
	}}}
}

func pbRange(name, label string, lo, hi int64, def *durationpb.Duration) *pb.Field {
	m := &pb.DurationModifiable{Range: &pb.DurationRange{Min: secs(lo), Max: secs(hi)}}
	if def != nil {
		m.DefaultValue = &pb.DurationValue{Value: def}
	}

	return &pb.Field{Name: name, Label: label, Type: &pb.Field_DurationField{DurationField: &pb.DurationField{
		Source: &pb.DurationField_Modifiable{Modifiable: m},
	}}}
}

func pbFixedDuration(name, label string, n int64) *pb.Field {
	return &pb.Field{Name: name, Label: label, Type: &pb.Field_DurationField{DurationField: &pb.DurationField{
		Source: &pb.DurationField_Fixed{Fixed: &pb.DurationValue{Value: secs(n)}},
	}}}
}

func assertProtoEqual(t *testing.T, got, want proto.Message) {
	t.Helper()

	if !proto.Equal(got, want) {
		t.Errorf("params differ\ngot:\n%s\nwant:\n%s", prototext.Format(got), prototext.Format(want))
	}
}

func TestBuildLabelsEachFieldAsItsTemplateSays(t *testing.T) {
	got, err := Build("oidc/generic", Binding{OIDCKeyID: []byte{9}}, []*pb.Field{
		FixedString("audience", "https://api.example.com"),
		FixedString("subject", "deploy-bot"),
		mustJSON(t, "claims", []Member{{"team", "platform"}, {"tier", 2}}),
		DurationRange("lifetime", 300, 900, new(int64(600))),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	claims := &pb.Field{Name: "claims", Label: "Claims", Type: &pb.Field_JsonObjectField{JsonObjectField: &pb.JsonObjectField{
		Source: &pb.JsonObjectField_Fixed{Fixed: &pb.JsonObjectValue{Members: []*pb.JsonObjectValue_Member{
			{Name: "team", Value: &pb.JsonObjectValue_Value{Kind: &pb.JsonObjectValue_Value_StringValue{StringValue: "platform"}}},
			{Name: "tier", Value: &pb.JsonObjectValue_Value{Kind: &pb.JsonObjectValue_Value_IntegerValue{IntegerValue: 2}}},
		}}},
	}}}
	want := &pb.CreateAppParams{
		Template: "oidc/generic",
		Title:    "Generic OIDC",
		Fields: []*pb.Field{
			pbFixed("audience", "Audience", "https://api.example.com"),
			pbFixed("subject", "Subject", "deploy-bot"),
			claims,
			pbRange("lifetime", "Token lifetime", 300, 900, secs(600)),
			pbDerived("token_id", "Token ID", pb.Derived_DERIVED_PER_SIGN_IN_ID),
		},
		App: &pb.CreateAppParams_Oidc{Oidc: &pb.OIDCCreateApp{
			KeyId: []byte{9},
			Layout: &pb.OIDCLayout{
				Subject:  expr(ref("subject")),
				Audience: expr(ref("audience")),
				Lifetime: &pb.OIDCLifetime{Lifetime: &pb.OIDCLifetime_Field{Field: &pb.FieldRef{Name: "lifetime"}}},
				TokenId:  &pb.FieldRef{Name: "token_id"},
				Claims:   []*pb.OIDCClaimLayout{{Value: expr(ref("claims"))}},
			},
		}},
	}
	assertProtoEqual(t, got, want)
}

func oidcAWSLayout(tags ...*pb.OIDCClaimLayout) *pb.OIDCLayout {
	return &pb.OIDCLayout{
		Subject:  expr(ref("subject")),
		Audience: expr(text("sts.amazonaws.com")),
		Lifetime: &pb.OIDCLifetime{Lifetime: &pb.OIDCLifetime_ExchangeWindow{ExchangeWindow: &emptypb.Empty{}}},
		TokenId:  &pb.FieldRef{Name: "token_id"},
		Claims: append([]*pb.OIDCClaimLayout{
			{Path: []string{"https://aws.amazon.com/roles"}, Value: expr(ref("role_arn")), WrapInList: true},
			{Path: []string{"https://aws.amazon.com/source_identity"}, Value: expr(ref("source_identity"))},
			{Path: []string{awsTags, principalTags, "SplitSecureTokenId"}, Value: expr(ref("token_id")), WrapInList: true},
		}, tags...),
		RequestedClientDuration: &pb.FieldRef{Name: "session_duration"},
	}
}

func oidcAWSImplicit() []*pb.Field {
	return []*pb.Field{
		pbDerived("subject", "Subject", pb.Derived_DERIVED_AT_CREATION_ID),
		pbRequester("source_identity", "Source identity", pb.Requester_REQUESTER_SESSION_NAME, nil),
		pbDerived("token_id", "Token ID", pb.Derived_DERIVED_PER_SIGN_IN_ID),
	}
}

func TestBuildNamesEachInstanceAfterItsFieldAndPlacesIt(t *testing.T) {
	got, err := Build("oidc/aws", Binding{OIDCKeyID: []byte{9}},
		[]*pb.Field{FixedString("role_arn", roleARN), DurationRange("session_duration", 900, 3600, nil)},
		[]Instance{
			{Key: "Project", Field: FixedString("session_tag", "billing")},
			{Key: "Env", Field: FixedString("session_tag", "dev")},
		})
	if err != nil {
		t.Fatal(err)
	}

	want := &pb.CreateAppParams{
		Template: "oidc/aws",
		Title:    "AWS (OIDC)",
		Fields: append([]*pb.Field{
			pbFixed("role_arn", "Role ARN", roleARN),
			pbRange("session_duration", "Session duration", 900, 3600, nil),
			pbFixed("session_tag_1", "Session tag", "billing"),
			pbFixed("session_tag_2", "Session tag", "dev"),
		}, oidcAWSImplicit()...),
		App: &pb.CreateAppParams_Oidc{Oidc: &pb.OIDCCreateApp{
			KeyId: []byte{9},
			Layout: oidcAWSLayout(
				&pb.OIDCClaimLayout{Path: []string{awsTags, principalTags, "Project"}, Value: expr(ref("session_tag_1")), WrapInList: true},
				&pb.OIDCClaimLayout{Path: []string{awsTags, principalTags, "Env"}, Value: expr(ref("session_tag_2")), WrapInList: true},
			),
		}},
	}
	assertProtoEqual(t, got, want)
}

func TestBuildOIDCAWSWithOneRequesterSessionTag(t *testing.T) {
	got, err := Build("oidc/aws", Binding{OIDCKeyID: []byte{1, 2, 3, 4}},
		[]*pb.Field{FixedString("role_arn", roleARN), FixedDuration("session_duration", 3600)},
		[]Instance{{Key: "Email", Field: RequesterString("session_tag", pb.Requester_REQUESTER_EMAIL, "@corp.example")}})
	if err != nil {
		t.Fatal(err)
	}

	want := &pb.CreateAppParams{
		Template: "oidc/aws",
		Title:    "AWS (OIDC)",
		Fields: append([]*pb.Field{
			pbFixed("role_arn", "Role ARN", roleARN),
			pbFixedDuration("session_duration", "Session duration", 3600),
			pbRequester("session_tag_1", "Session tag", pb.Requester_REQUESTER_EMAIL, &pb.StringAffix{Suffix: "@corp.example"}),
		}, oidcAWSImplicit()...),
		App: &pb.CreateAppParams_Oidc{Oidc: &pb.OIDCCreateApp{
			KeyId: []byte{1, 2, 3, 4},
			Layout: oidcAWSLayout(
				&pb.OIDCClaimLayout{Path: []string{awsTags, principalTags, "Email"}, Value: expr(ref("session_tag_1")), WrapInList: true},
			),
		}},
	}
	assertProtoEqual(t, got, want)
}

func TestBuildSAML2AWSWithSessionRangeAndTwoTags(t *testing.T) {
	meta := MinimalSPMetadata("urn:amazon:webservices", "https://signin.aws.amazon.com/saml")
	fields := []*pb.Field{
		FixedString("saml_provider_arn", providerARN),
		FixedString("role_arn", roleARN),
		DurationRange("session_duration", 900, 3600, new(int64(1800))),
		FixedString("name_id_format", emailFormat),
		FixedString("name_id", "ops@corp.example"),
	}
	instances := []Instance{
		{Key: "Team", Field: FixedString("session_tag", "platform")},
		{Key: "Email", Field: RequesterString("session_tag", pb.Requester_REQUESTER_EMAIL, "")},
	}
	before := proto.CloneOf(fields[0])

	got, err := Build("saml2/aws", Binding{SAML2: meta}, fields, instances)
	if err != nil {
		t.Fatal(err)
	}

	want := &pb.CreateAppParams{
		Template: "saml2/aws",
		Title:    "AWS (SAML)",
		Fields: []*pb.Field{
			pbFixed("saml_provider_arn", "SAML provider ARN", providerARN),
			pbFixed("role_arn", "Role ARN", roleARN),
			pbRange("session_duration", "Session duration", 900, 3600, secs(1800)),
			pbFixed("name_id_format", "NameID format", emailFormat),
			pbFixed("name_id", "NameID", "ops@corp.example"),
			pbFixed("session_tag_1", "Session tag", "platform"),
			pbRequester("session_tag_2", "Session tag", pb.Requester_REQUESTER_EMAIL, nil),
			pbRequester("role_session_name", "Role session name", pb.Requester_REQUESTER_SESSION_NAME, nil),
		},
		App: &pb.CreateAppParams_Saml2{Saml2: &pb.SAML2CreateApp{
			SpMetadata: meta,
			Layout: &pb.SAML2Layout{
				Audience: &pb.SAML2Audience{Audience: &pb.SAML2Audience_Fixed{Fixed: "https://signin.aws.amazon.com/saml"}},
				NameId:   &pb.SAML2NameIDLayout{Format: expr(ref("name_id_format")), Value: expr(ref("name_id"))},
				Attributes: []*pb.SAML2AttributeLayout{
					{Name: "https://aws.amazon.com/SAML/Attributes/Role", Value: expr(ref("role_arn"), text(","), ref("saml_provider_arn"))},
					{Name: "https://aws.amazon.com/SAML/Attributes/RoleSessionName", Value: expr(ref("role_session_name"))},
					{
						Name:  "https://aws.amazon.com/SAML/Attributes/SessionDuration",
						Value: expr(&pb.ExprPart{Part: &pb.ExprPart_DurationSeconds{DurationSeconds: &pb.FieldRef{Name: "session_duration"}}}),
					},
					{Name: principalTagAt + "Team", Value: expr(ref("session_tag_1"))},
					{Name: principalTagAt + "Email", Value: expr(ref("session_tag_2"))},
				},
			},
		}},
	}
	assertProtoEqual(t, got, want)

	if !proto.Equal(fields[0], before) || fields[0].GetLabel() != "" || instances[0].Field.GetName() != "session_tag" {
		t.Error("Build modified its inputs")
	}
}

func TestBuildReplacesNameIDWhereTheLayoutPlacesIt(t *testing.T) {
	meta := MinimalSPMetadata("google.com", "https://www.google.com/a/example.com/acs")

	got, err := Build("saml2/google-workspace-legacy", Binding{SAML2: meta}, []*pb.Field{
		FixedString("name_id_format", emailFormat),
		RequesterString("requester_email", pb.Requester_REQUESTER_EMAIL, ""),
	}, nil, WithNameID(FieldPart("requester_email")))
	if err != nil {
		t.Fatal(err)
	}

	want := &pb.CreateAppParams{
		Template: "saml2/google-workspace-legacy",
		Title:    "Google Workspace Legacy",
		Fields: []*pb.Field{
			pbFixed("name_id_format", "NameID format", emailFormat),
			pbRequester("requester_email", "Requester's email", pb.Requester_REQUESTER_EMAIL, nil),
		},
		App: &pb.CreateAppParams_Saml2{Saml2: &pb.SAML2CreateApp{
			SpMetadata: meta,
			Layout: &pb.SAML2Layout{
				Audience:   &pb.SAML2Audience{Audience: &pb.SAML2Audience_EntityId{EntityId: &emptypb.Empty{}}},
				NameId:     &pb.SAML2NameIDLayout{Format: expr(ref("name_id_format")), Value: expr(ref("requester_email"))},
				Attributes: []*pb.SAML2AttributeLayout{{Name: "Email", Value: expr(ref("requester_email"))}},
			},
		}},
	}
	assertProtoEqual(t, got, want)
}

func TestBuildDropsLayoutEntriesOfUnsetOptionalFields(t *testing.T) {
	meta := MinimalSPMetadata("https://pagerduty.example", "https://pagerduty.example/sso/saml/consume")

	got, err := Build("saml2/pagerduty", Binding{SAML2: meta}, []*pb.Field{
		FixedString("name_id_format", emailFormat),
		RequesterString("requester_email", pb.Requester_REQUESTER_EMAIL, ""),
		FixedString("role", "observer"),
	}, nil, WithNameID(FieldPart("requester_email")))
	if err != nil {
		t.Fatal(err)
	}

	want := []*pb.SAML2AttributeLayout{
		{Name: "email", Value: expr(ref("requester_email"))},
		{Name: "role", Value: expr(ref("role"))},
	}
	assertProtoEqual(t, &pb.SAML2Layout{Attributes: got.GetSaml2().GetLayout().GetAttributes()}, &pb.SAML2Layout{Attributes: want})

	oidc, err := Build("oidc/generic", Binding{OIDCKeyID: []byte{9}}, []*pb.Field{
		FixedString("audience", "https://api.example.com"),
		DerivedString("subject", pb.Derived_DERIVED_AT_CREATION_ID),
		FixedDuration("lifetime", 600),
	}, nil)
	if err != nil {
		t.Fatal(err)
	}

	if n := len(oidc.GetOidc().GetLayout().GetClaims()); n != 0 {
		t.Errorf("claims layout has %d entries, want 0 without the claims field", n)
	}
}

func TestBuildPlacesGenericSAMLAttributesUnderTheirKey(t *testing.T) {
	got, err := Build("saml2/generic", Binding{SAML2: MinimalSPMetadata("sp", "https://sp/acs")}, []*pb.Field{
		FixedString("name_id_format", emailFormat),
		ModifiableString("name_id", ModifiableStringOptions{Affix: &Affix{Suffix: "@corp.example", MaxLength: 64}}),
	}, []Instance{{Key: "groups", Field: FixedStringList("attribute", []string{"admins", "oncall"})}})
	if err != nil {
		t.Fatal(err)
	}

	attrs := got.GetSaml2().GetLayout().GetAttributes()
	want := &pb.SAML2AttributeLayout{Name: "groups", Value: expr(ref("attribute_1"))}

	if len(attrs) != 1 || !proto.Equal(attrs[0], want) {
		t.Errorf("attributes = %v, want [%v]", attrs, want)
	}
}

func TestBuildRefuses(t *testing.T) {
	oidc := Binding{OIDCKeyID: []byte{9}}
	saml := Binding{SAML2: MinimalSPMetadata("sp", "https://sp/acs")}
	generic := []*pb.Field{FixedString("audience", "https://api.example.com"), FixedString("subject", "deploy-bot"), FixedDuration("lifetime", 600)}
	awsSAML := []*pb.Field{
		FixedString("saml_provider_arn", providerARN),
		FixedString("role_arn", roleARN),
		FixedDuration("session_duration", 3600),
		FixedString("name_id_format", emailFormat),
	}
	awsWithDuration := func(d *pb.Field) []*pb.Field { return []*pb.Field{awsSAML[0], awsSAML[1], d, awsSAML[3]} }
	modifiableAudience := ModifiableString("audience", ModifiableStringOptions{Choices: []string{"a"}})
	emailSessionName := RequesterString("role_session_name", pb.Requester_REQUESTER_EMAIL, "")
	derivedTag := DerivedString("session_tag", pb.Derived_DERIVED_PER_SIGN_IN_ID)
	persistent := FixedString("name_id_format", "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent")
	awsNameID := append(slices.Clone(awsSAML), DerivedString("name_id", pb.Derived_DERIVED_PER_SIGN_IN_ID))
	tag := FixedString("session_tag", "v")
	oidcAWS := []*pb.Field{FixedString("role_arn", roleARN), FixedDuration("session_duration", 3600)}
	oktaFields := func(amr *pb.Field) []*pb.Field {
		return []*pb.Field{FixedString("name_id_format", emailFormat), FixedString("name_id", "alice@example.com"), amr}
	}
	listDefaultC := ModifiableStringList("claim_list", []string{"a", "b"}, []string{"c"})
	emptyAffixTag := ModifiableString("session_tag", ModifiableStringOptions{Affix: &Affix{}})
	chosenNameID := ModifiableString("name_id", ModifiableStringOptions{Choices: []string{"jane@example.com"}})

	tests := []struct {
		name      string
		template  string
		binding   Binding
		fields    []*pb.Field
		instances []Instance
		opts      []Option
		want      error
	}{
		{name: "unknown template", template: "saml2/unknown", binding: saml, want: ErrUnknownTemplate},
		{name: "SAML2 binding for an OIDC template", template: "oidc/generic", binding: saml, fields: generic, want: ErrBinding},
		{name: "both bindings", template: "oidc/generic", binding: Binding{SAML2: saml.SAML2, OIDCKeyID: oidc.OIDCKeyID}, fields: generic, want: ErrBinding},
		{name: "no binding", template: "oidc/generic", fields: generic, want: ErrBinding},
		{name: "NameID on OIDC", template: "oidc/generic", binding: oidc, fields: generic, opts: []Option{WithNameID(TextPart("x"))}, want: ErrNameID},
		{name: "NameID field unset", template: "saml2/aws", binding: saml, fields: awsSAML, want: ErrRequired},
		{name: "NameID part names an unset field", template: "saml2/aws", binding: saml, fields: awsSAML, opts: []Option{WithNameID(FieldPart("requester_email"))}, want: ErrRequired},
		{name: "field the template lacks", template: "oidc/generic", binding: oidc, fields: append(slices.Clone(generic), FixedString("nope", "x")), want: ErrUnknownField},
		{name: "repeatable field given as a field", template: "oidc/aws", binding: oidc, fields: []*pb.Field{FixedString("role_arn", roleARN), FixedString("session_tag", "billing")}, want: ErrInstanceOnly},
		{name: "required field unset", template: "oidc/generic", binding: oidc, fields: generic[:1], want: ErrRequired},
		{name: "instance of a plain field", template: "oidc/aws", binding: oidc, fields: generic[:0], instances: []Instance{{Key: "k", Field: FixedString("role_arn", roleARN)}}, want: ErrNotRepeatable},
		{name: "instance of an unknown field", template: "oidc/aws", binding: oidc, instances: []Instance{{Key: "k", Field: FixedString("tag", "v")}}, want: ErrNotRepeatable},
		{name: "wrong type", template: "oidc/generic", binding: oidc, fields: []*pb.Field{generic[0], generic[1], FixedString("lifetime", "600")}, want: ErrFieldType},
		{name: "source not allowed", template: "oidc/generic", binding: oidc, fields: []*pb.Field{modifiableAudience, generic[1], generic[2]}, want: ErrSource},
		{name: "requester kind not allowed", template: "saml2/aws", binding: saml, fields: append(slices.Clone(awsSAML), emailSessionName), want: ErrSource},
		{name: "instance source not allowed", template: "oidc/aws", binding: oidc, instances: []Instance{{Key: "k", Field: derivedTag}}, want: ErrSource},
		{name: "value outside choices", template: "saml2/aws", binding: saml, fields: append(slices.Clone(awsSAML[:3]), FixedString("name_id_format", "bogus")), want: ErrValue},
		{name: "duration below bounds", template: "saml2/aws", binding: saml, fields: awsWithDuration(FixedDuration("session_duration", 60)), want: ErrValue},
		{name: "range minimum above maximum", template: "saml2/aws", binding: saml, fields: awsWithDuration(DurationRange("session_duration", 3600, 900, nil)), want: ErrValue},
		{name: "range default outside its own range", template: "saml2/aws", binding: saml, fields: awsWithDuration(DurationRange("session_duration", 1800, 3600, new(int64(900)))), want: ErrValue},
		{name: "duration not in whole minutes", template: "saml2/aws", binding: saml, fields: awsWithDuration(FixedDuration("session_duration", 901)), want: ErrValue},
		{name: "fixed list outside the template's choices", template: "saml2/okta", binding: saml, fields: oktaFields(FixedStringList("session_amr", []string{"phr", "anything"})), want: ErrValue},
		{name: "same field twice", template: "saml2/generic", binding: saml, fields: []*pb.Field{persistent, FixedString("name_id", "a"), FixedString("name_id", "b")}, want: ErrDuplicate},
		{name: "empty instance key", template: "saml2/aws", binding: saml, fields: awsNameID, instances: []Instance{{Key: "", Field: tag}}, want: ErrInstanceKey},
		{name: "instance key twice", template: "saml2/aws", binding: saml, fields: awsNameID, instances: []Instance{{Key: "team", Field: tag}, {Key: "team", Field: tag}}, want: ErrDuplicate},
		{name: "list default outside its choices", template: "oidc/generic", binding: oidc, fields: generic, instances: []Instance{{Key: "k", Field: listDefaultC}}, want: ErrValue},
		{name: "affix with no part", template: "oidc/aws", binding: oidc, fields: oidcAWS, instances: []Instance{{Key: "k", Field: emptyAffixTag}}, want: ErrValue},
		{name: "AWS NameID chosen at sign-in", template: "saml2/aws", binding: saml, fields: append(slices.Clone(awsSAML), chosenNameID), want: ErrSource},
		{name: "name_id field and a NameID", template: "saml2/generic", binding: saml, fields: oktaFields(nil)[:2], opts: []Option{WithNameID(TextPart("bob@example.com"))}, want: ErrNameID},
		{name: "NameID with no part", template: "saml2/generic", binding: saml, fields: []*pb.Field{persistent}, opts: []Option{WithNameID([]*pb.ExprPart{}...)}, want: ErrNameID},
		{name: "NameID part names an undeclared field", template: "saml2/generic", binding: saml, fields: oktaFields(nil)[:1], opts: []Option{WithNameID(FieldPart("nope"))}, want: ErrUnknownField},
		{name: "unknown value of an undeclared field", template: "oidc/generic", binding: oidc, fields: generic, opts: []Option{WithUnknown("nope")}, want: ErrUnknownField},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			_, err := Build(tt.template, tt.binding, tt.fields, tt.instances, tt.opts...)
			if !errors.Is(err, tt.want) {
				t.Errorf("Build() error = %v, want %v", err, tt.want)
			}
		})
	}
}

func TestBuildNamesTheFieldItRefuses(t *testing.T) {
	saml := Binding{SAML2: MinimalSPMetadata("sp", "https://sp/acs")}
	format := FixedString("name_id_format", emailFormat)

	_, err := Build("saml2/generic", saml, []*pb.Field{format}, nil, WithNameID(FieldPart("requester_email")))
	if !errors.Is(err, ErrRequired) || !strings.Contains(err.Error(), "requester_email") {
		t.Errorf("unset NameID part: err = %v, want ErrRequired naming requester_email", err)
	}

	_, err = Build("saml2/generic", saml, []*pb.Field{format, FixedString("name_id", "a@example.com"), FixedString("name_id", "b@example.com")}, nil)

	var fe *FieldError
	if !errors.As(err, &fe) || fe.Name != "name_id" || fe.Instance {
		t.Errorf("field given twice: err = %#v, want a FieldError for name_id", err)
	}

	_, err = Build("oidc/aws", Binding{OIDCKeyID: []byte{9}}, []*pb.Field{FixedString("role_arn", roleARN), FixedDuration("session_duration", 3600)},
		[]Instance{{Key: "team", Field: FixedString("session_tag", "a")}, {Key: "team", Field: FixedString("session_tag", "b")}})
	if !errors.As(err, &fe) || fe.Name != "session_tag" || fe.Key != "team" || !fe.Instance {
		t.Errorf("instance key twice: err = %#v, want a FieldError for the session_tag instance team", err)
	}
}

func TestBuildCountsUnknownFieldsAsSet(t *testing.T) {
	saml := Binding{SAML2: MinimalSPMetadata("sp", "https://sp/acs")}
	fields := []*pb.Field{FixedString("saml_provider_arn", providerARN), FixedString("name_id_format", emailFormat)}

	_, err := Build("saml2/aws", saml, fields, nil, WithUnknown("role_arn", "session_duration", "name_id"))
	if err != nil {
		t.Errorf("Build() error = %v, want the unknown fields counted as set", err)
	}
}

func TestMinimalSPMetadata(t *testing.T) {
	want := &samlv2.Metadata{Content: &samlv2.Metadata_EntityDescriptor{EntityDescriptor: &samlv2.EntityDescriptor{
		EntityId: "https://sp.example/entity",
		SpSsoDescriptor: []*samlv2.SPSSODescriptor{{AssertionConsumerService: []*samlv2.IndexedEndpoint{{
			Base:      &samlv2.Endpoint{Binding: "urn:oasis:names:tc:SAML:2.0:bindings:HTTP-POST", Location: "https://sp.example/acs"},
			IsDefault: true,
		}}}},
	}}}
	assertProtoEqual(t, MinimalSPMetadata("https://sp.example/entity", "https://sp.example/acs"), want)
}
