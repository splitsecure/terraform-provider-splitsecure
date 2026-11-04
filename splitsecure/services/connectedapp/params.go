package connectedapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/types"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	catalog "github.com/splitsecure/terraform-provider-splitsecure/splitsecure/connectedapp"
)

// HCL values of a field's requester and derived sources.
const (
	requesterEmail       = "email"
	requesterSessionName = "session_name"
	derivedAtCreation    = "at_creation"
	derivedPerSignIn     = "per_sign_in"
	fieldPartPrefix      = "field:"
)

var (
	errFieldShape    = errors.New("set exactly one of value, values, seconds, duration_range, choices with its default, requester, derived and json")
	errListDefault   = errors.New("a list field chosen at sign-in takes default_values, not default_value")
	errTextDefaults  = errors.New("a text field chosen at sign-in takes default_value, not default_values")
	errSuffix        = errors.New("suffix applies only to a requester field")
	errNoChoices     = errors.New("a field chosen at sign-in needs choices, and the template lists none")
	errJSONObject    = errors.New("json must hold one JSON object")
	errUnknownSource = errors.New("unknown source value")
	errListElement   = errors.New("list holds a null value")

	errListAffix       = errors.New("an affix applies only to a text field chosen at sign-in")
	errChoicesAndAffix = errors.New("set choices or affix, not both")
	errMaxLength       = errors.New("max_length must be from 0 to 4294967295")
)

// params builds the create params from a fully known model, reporting each problem at its attribute.
func params(ctx context.Context, m *appModel) (*pb.CreateAppParams, diag.Diagnostics) {
	var diags diag.Diagnostics

	binding := bindingFromModel(ctx, m, &diags)
	if diags.HasError() {
		return nil, diags
	}

	tmpl, err := catalog.Lookup(m.Template.ValueString())
	if err != nil {
		diags.AddAttributeError(path.Root("template"), "Unknown template", err.Error())

		return nil, diags
	}

	fields, instances := fieldsFromModel(ctx, m.Fields, tmpl, &diags)
	opts := nameIDOptions(ctx, m.NameID, &diags)

	if diags.HasError() {
		return nil, diags
	}

	built, err := catalog.Build(tmpl.Name, binding, fields, instances, opts...)
	if err != nil {
		diags.AddError("Invalid connected app", err.Error())

		return nil, diags
	}

	return built, diags
}

func bindingFromModel(ctx context.Context, m *appModel, diags *diag.Diagnostics) catalog.Binding {
	var (
		saml2 []saml2Model
		oidc  []oidcModel
	)

	diags.Append(m.SAML2.ElementsAs(ctx, &saml2, false)...)
	diags.Append(m.OIDC.ElementsAs(ctx, &oidc, false)...)

	if diags.HasError() {
		return catalog.Binding{}
	}

	if len(saml2)+len(oidc) != 1 {
		diags.AddAttributeError(path.Root("saml2"), "Invalid binding", "Set exactly one saml2 or oidc block.")

		return catalog.Binding{}
	}

	if len(saml2) == 1 {
		return samlBinding(&saml2[0], diags)
	}

	keyID, err := base64.StdEncoding.DecodeString(oidc[0].KeyID.ValueString())
	if err != nil || len(keyID) == 0 {
		diags.AddAttributeError(path.Root("oidc").AtListIndex(0).AtName("key_id"), "Invalid key id", "key_id must be the non-empty base64 key id the issuer exports.")

		return catalog.Binding{}
	}

	return catalog.Binding{OIDCKeyID: keyID}
}

// samlBinding returns the SP metadata of a saml2 block: from entity_id and acs_url, or parsed from metadata_xml.
func samlBinding(m *saml2Model, diags *diag.Diagnostics) catalog.Binding {
	at := path.Root("saml2").AtListIndex(0)

	simple, problem := samlForm(m)
	if problem != "" {
		diags.AddAttributeError(at, "Invalid saml2 block", problem)

		return catalog.Binding{}
	}

	if simple {
		return catalog.Binding{SAML2: catalog.MinimalSPMetadata(m.EntityID.ValueString(), m.ACSURL.ValueString())}
	}

	md, err := parseMetadata(m.MetadataXML.ValueString())
	if err != nil {
		diags.AddAttributeError(at.AtName("metadata_xml"), "Invalid metadata_xml", err.Error())

		return catalog.Binding{}
	}

	return catalog.Binding{SAML2: md}
}

// samlForm reports whether the block uses entity_id and acs_url rather than metadata_xml, or what is wrong with it.
func samlForm(m *saml2Model) (bool, string) {
	simple := !m.EntityID.IsNull() || !m.ACSURL.IsNull()

	switch {
	case simple && !m.MetadataXML.IsNull():
		return false, "Set entity_id and acs_url, or metadata_xml, not both."
	case simple && (m.EntityID.IsNull() || m.ACSURL.IsNull()):
		return false, "Set both entity_id and acs_url."
	case !simple && m.MetadataXML.IsNull():
		return false, "Set entity_id and acs_url, or metadata_xml."
	}

	return simple, ""
}

func fieldsFromModel(ctx context.Context, list types.List, tmpl *catalog.Template, diags *diag.Diagnostics) ([]*pb.Field, []catalog.Instance) {
	var models []fieldModel

	diags.Append(list.ElementsAs(ctx, &models, false)...)

	if diags.HasError() {
		return nil, nil
	}

	var (
		fields    []*pb.Field
		instances []catalog.Instance
	)

	for i, fm := range models {
		spec, _ := tmpl.Spec(fm.Name.ValueString())

		f, err := fm.field(ctx, spec)
		if err != nil {
			diags.AddAttributeError(path.Root("field").AtListIndex(i), "Invalid field "+fm.Name.ValueString(), err.Error())

			continue
		}

		if fm.Key.IsNull() {
			fields = append(fields, f)

			continue
		}

		instances = append(instances, catalog.Instance{Key: fm.Key.ValueString(), Field: f})
	}

	return fields, instances
}

// field returns the field fm describes. spec, when known, supplies the choices of a field chosen at sign-in.
func (fm *fieldModel) field(ctx context.Context, spec *catalog.FieldSpec) (*pb.Field, error) {
	err := fm.checkShape()
	if err != nil {
		return nil, err
	}

	name := fm.Name.ValueString()

	switch {
	case !fm.Value.IsNull():
		return catalog.FixedString(name, fm.Value.ValueString()), nil
	case !fm.Values.IsNull():
		values, err := stringElements(ctx, fm.Values)
		if err != nil {
			return nil, err
		}

		return catalog.FixedStringList(name, values), nil
	case !fm.Seconds.IsNull():
		return catalog.FixedDuration(name, fm.Seconds.ValueInt64()), nil
	case fm.modifiable():
		return fm.chosenAtSignIn(ctx, spec)
	case !fm.Requester.IsNull():
		return fm.requesterString()
	case !fm.Derived.IsNull():
		return fm.derivedString()
	case !fm.JSON.IsNull():
		return jsonField(name, fm.JSON.ValueString())
	}

	return fm.durationRange(ctx)
}

func (fm *fieldModel) modifiable() bool {
	return !fm.Choices.IsNull() || !fm.DefaultValue.IsNull() || !fm.DefaultValues.IsNull() || len(fm.Affix.Elements()) > 0
}

// checkShape refuses a field with no source, with several, or with a suffix that has no requester to hold.
func (fm *fieldModel) checkShape() error {
	set := 0

	for _, isSet := range []bool{
		!fm.Value.IsNull(), !fm.Values.IsNull(), !fm.Seconds.IsNull(), len(fm.DurationRange.Elements()) > 0,
		fm.modifiable(), !fm.Requester.IsNull(), !fm.Derived.IsNull(), !fm.JSON.IsNull(),
	} {
		if isSet {
			set++
		}
	}

	if set != 1 {
		return errFieldShape
	}

	if !fm.Suffix.IsNull() && fm.Requester.IsNull() {
		return errSuffix
	}

	return nil
}

// chosenAtSignIn returns a text or list field each sign-in chooses from choices, by the type the spec gives the field.
func (fm *fieldModel) chosenAtSignIn(ctx context.Context, spec *catalog.FieldSpec) (*pb.Field, error) {
	isList := spec != nil && spec.Type == catalog.TypeStringList

	err := fm.checkChosen(isList)
	if err != nil {
		return nil, err
	}

	if len(fm.Affix.Elements()) > 0 {
		return fm.affixString(ctx)
	}

	choices, err := fm.choices(ctx, spec)
	if err != nil {
		return nil, err
	}

	if isList {
		return fm.modifiableList(ctx, choices)
	}

	opts := catalog.ModifiableStringOptions{Choices: choices}
	if !fm.DefaultValue.IsNull() {
		opts.Default = new(fm.DefaultValue.ValueString())
	}

	return catalog.ModifiableString(fm.Name.ValueString(), opts), nil
}

// checkChosen refuses a default or an affix of the other field type, and choices set beside an affix.
func (fm *fieldModel) checkChosen(isList bool) error {
	hasAffix := len(fm.Affix.Elements()) > 0

	switch {
	case isList && !fm.DefaultValue.IsNull():
		return errListDefault
	case !isList && !fm.DefaultValues.IsNull():
		return errTextDefaults
	case hasAffix && isList:
		return errListAffix
	case hasAffix && !fm.Choices.IsNull():
		return errChoicesAndAffix
	}

	return nil
}

// affixString returns a text field each sign-in sets within the affix, else to default_value.
func (fm *fieldModel) affixString(ctx context.Context) (*pb.Field, error) {
	var affixes []affixModel

	diags := fm.Affix.ElementsAs(ctx, &affixes, false)
	if diags.HasError() || len(affixes) != 1 {
		return nil, errFieldShape
	}

	a := affixes[0]
	if a.MaxLength.ValueInt64() < 0 || a.MaxLength.ValueInt64() > math.MaxUint32 {
		return nil, errMaxLength
	}

	opts := catalog.ModifiableStringOptions{Affix: &catalog.Affix{
		Prefix:    a.Prefix.ValueString(),
		Suffix:    a.Suffix.ValueString(),
		MaxLength: uint32(a.MaxLength.ValueInt64()), //nolint:gosec // bounded to uint32 above.
	}}
	if !fm.DefaultValue.IsNull() {
		opts.Default = new(fm.DefaultValue.ValueString())
	}

	return catalog.ModifiableString(fm.Name.ValueString(), opts), nil
}

// choices returns the configured choices, else the template's choices for the field.
func (fm *fieldModel) choices(ctx context.Context, spec *catalog.FieldSpec) ([]string, error) {
	choices, err := stringElements(ctx, fm.Choices)
	if err != nil {
		return nil, err
	}

	if len(choices) == 0 && spec != nil {
		choices = spec.Choices
	}

	if len(choices) == 0 {
		return nil, errNoChoices
	}

	return choices, nil
}

func (fm *fieldModel) modifiableList(ctx context.Context, choices []string) (*pb.Field, error) {
	if fm.DefaultValues.IsNull() {
		return catalog.ModifiableStringList(fm.Name.ValueString(), choices, nil), nil
	}

	defaults, err := stringElements(ctx, fm.DefaultValues)
	if err != nil {
		return nil, err
	}

	return catalog.ModifiableStringList(fm.Name.ValueString(), choices, defaults), nil
}

func (fm *fieldModel) requesterString() (*pb.Field, error) {
	kinds := map[string]pb.Requester{
		requesterEmail:       pb.Requester_REQUESTER_EMAIL,
		requesterSessionName: pb.Requester_REQUESTER_SESSION_NAME,
	}

	kind, ok := kinds[fm.Requester.ValueString()]
	if !ok {
		return nil, fmt.Errorf("%w: requester %q", errUnknownSource, fm.Requester.ValueString())
	}

	return catalog.RequesterString(fm.Name.ValueString(), kind, fm.Suffix.ValueString()), nil
}

func (fm *fieldModel) derivedString() (*pb.Field, error) {
	kinds := map[string]pb.Derived{
		derivedAtCreation: pb.Derived_DERIVED_AT_CREATION_ID,
		derivedPerSignIn:  pb.Derived_DERIVED_PER_SIGN_IN_ID,
	}

	kind, ok := kinds[fm.Derived.ValueString()]
	if !ok {
		return nil, fmt.Errorf("%w: derived %q", errUnknownSource, fm.Derived.ValueString())
	}

	return catalog.DerivedString(fm.Name.ValueString(), kind), nil
}

func (fm *fieldModel) durationRange(ctx context.Context) (*pb.Field, error) {
	var ranges []durationRangeModel

	diags := fm.DurationRange.ElementsAs(ctx, &ranges, false)
	if diags.HasError() || len(ranges) != 1 {
		return nil, errFieldShape
	}

	r := ranges[0]

	var def *int64
	if !r.DefaultSeconds.IsNull() {
		def = new(r.DefaultSeconds.ValueInt64())
	}

	return catalog.DurationRange(fm.Name.ValueString(), r.MinSeconds.ValueInt64(), r.MaxSeconds.ValueInt64(), def), nil
}

// jsonField decodes raw as one JSON object, keeping member order and exact numbers.
func jsonField(name, raw string) (*pb.Field, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()

	tok, err := dec.Token()
	if err != nil || tok != json.Delim('{') {
		return nil, errJSONObject
	}

	members, err := jsonMembers(dec)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errJSONObject, err)
	}

	_, err = dec.Token()
	if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data after the object", errJSONObject)
	}

	f, err := catalog.FixedJSONObject(name, members)
	if err != nil {
		return nil, fmt.Errorf("decoding json: %w", err)
	}

	return f, nil
}

// jsonMembers reads an object's members up to its closing brace, the opening one already read.
func jsonMembers(dec *json.Decoder) ([]catalog.Member, error) {
	var out []catalog.Member

	for dec.More() {
		tok, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("reading a member name: %w", err)
		}

		name, ok := tok.(string)
		if !ok {
			return nil, errJSONObject
		}

		v, err := jsonValue(dec)
		if err != nil {
			return nil, err
		}

		out = append(out, catalog.Member{Name: name, Value: v})
	}

	_, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("reading the end of an object: %w", err)
	}

	return out, nil
}

// jsonValue reads one value: an object as members in order, an array as a list, a number as json.Number.
func jsonValue(dec *json.Decoder) (any, error) {
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("reading a value: %w", err)
	}

	switch tok {
	case json.Delim('{'):
		return jsonMembers(dec)
	case json.Delim('['):
		var items []any

		for dec.More() {
			v, err := jsonValue(dec)
			if err != nil {
				return nil, err
			}

			items = append(items, v)
		}

		_, err := dec.Token()
		if err != nil {
			return nil, fmt.Errorf("reading the end of a list: %w", err)
		}

		return items, nil
	}

	return tok, nil
}

func nameIDOptions(ctx context.Context, list types.List, diags *diag.Diagnostics) []catalog.Option {
	var models []nameIDModel

	diags.Append(list.ElementsAs(ctx, &models, false)...)

	if diags.HasError() || len(models) == 0 {
		return nil
	}

	raw, err := stringElements(ctx, models[0].Parts)
	if err != nil {
		diags.AddAttributeError(path.Root("name_id").AtListIndex(0).AtName("parts"), "Invalid NameID parts", err.Error())

		return nil
	}

	parts := make([]*pb.ExprPart, 0, len(raw))

	for _, s := range raw {
		if name, ok := strings.CutPrefix(s, fieldPartPrefix); ok {
			parts = append(parts, catalog.FieldPart(name))

			continue
		}

		parts = append(parts, catalog.TextPart(s))
	}

	return []catalog.Option{catalog.WithNameID(parts...)}
}

func stringElements(ctx context.Context, list types.List) ([]string, error) {
	var out []string

	diags := list.ElementsAs(ctx, &out, false)
	if diags.HasError() {
		return nil, errListElement
	}

	return out, nil
}
