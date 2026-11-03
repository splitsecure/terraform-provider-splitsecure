package connectedapp

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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
		return catalog.Binding{SAML2: catalog.MinimalSPMetadata(saml2[0].EntityID.ValueString(), saml2[0].ACSURL.ValueString())}
	}

	keyID, err := base64.StdEncoding.DecodeString(oidc[0].KeyID.ValueString())
	if err != nil || len(keyID) == 0 {
		diags.AddAttributeError(path.Root("oidc").AtListIndex(0).AtName("key_id"), "Invalid key id", "key_id must be the non-empty base64 key id the issuer exports.")

		return catalog.Binding{}
	}

	return catalog.Binding{OIDCKeyID: keyID}
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
	return !fm.Choices.IsNull() || !fm.DefaultValue.IsNull() || !fm.DefaultValues.IsNull()
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

	switch {
	case isList && !fm.DefaultValue.IsNull():
		return nil, errListDefault
	case !isList && !fm.DefaultValues.IsNull():
		return nil, errTextDefaults
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

// jsonField decodes raw as one JSON object, keeping numbers exact.
func jsonField(name, raw string) (*pb.Field, error) {
	dec := json.NewDecoder(strings.NewReader(raw))
	dec.UseNumber()

	var v any

	err := dec.Decode(&v)
	if err != nil {
		return nil, fmt.Errorf("%w: %w", errJSONObject, err)
	}

	obj, ok := v.(map[string]any)
	if !ok {
		return nil, errJSONObject
	}

	_, err = dec.Token()
	if !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data after the object", errJSONObject)
	}

	f, err := catalog.FixedJSONObjectFromMap(name, obj)
	if err != nil {
		return nil, fmt.Errorf("decoding json: %w", err)
	}

	return f, nil
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
