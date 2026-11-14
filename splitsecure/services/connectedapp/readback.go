package connectedapp

import (
	"bytes"
	"cmp"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/proto"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	catalog "github.com/splitsecure/terraform-provider-splitsecure/splitsecure/connectedapp"
)

var (
	errUnexpressible = errors.New("the record holds a value the provider cannot express")
	errNoBinding     = errors.New("the record has no SAML2 or OIDC app")
)

// canonical is a connected app as a create describes it, with what does not change its meaning removed: labels,
// the order of the fields, and the names a create gives the instances of a repeatable field.
type canonical struct {
	template  string
	binding   proto.Message
	fields    map[string]*pb.Field
	instances []instance
	layout    proto.Message
}

// instance is one instance of a repeatable field, by the field and the key its layout entry carries it under.
type instance struct {
	field string
	key   string
	value *pb.Field
}

func (c *canonical) equal(o *canonical) bool {
	if c.template != o.template || !proto.Equal(c.binding, o.binding) || !proto.Equal(c.layout, o.layout) {
		return false
	}

	return sameFields(c.fields, o.fields) && slices.EqualFunc(c.instances, o.instances, func(a, b instance) bool {
		return a.field == b.field && a.key == b.key && proto.Equal(a.value, b.value)
	})
}

func sameFields(a, b map[string]*pb.Field) bool {
	if len(a) != len(b) {
		return false
	}

	for name, f := range a {
		if !proto.Equal(f, b[name]) {
			return false
		}
	}

	return true
}

// recordAsCreate returns the create a record stores, with its binding as the create carried it.
func recordAsCreate(app *pb.ConnectedAppParams) (*pb.CreateAppParams, error) {
	out := &pb.CreateAppParams{Template: app.GetTemplate(), Title: app.GetTitle(), Fields: app.GetFields()}

	switch {
	case app.GetSaml2() != nil:
		out.App = &pb.CreateAppParams_Saml2{Saml2: &pb.SAML2CreateApp{
			SpMetadata: app.GetSaml2().GetBinding().GetSpMetadata(),
			Layout:     app.GetSaml2().GetLayout(),
		}}
	case app.GetOidc() != nil:
		out.App = &pb.CreateAppParams_Oidc{Oidc: &pb.OIDCCreateApp{
			KeyId:  app.GetOidc().GetBinding().GetKeyId(),
			Layout: app.GetOidc().GetLayout(),
		}}
	default:
		return nil, errNoBinding
	}

	return out, nil
}

// canonicalOf returns the canonical form of a create for template t.
func canonicalOf(t *catalog.Template, p *pb.CreateAppParams) *canonical {
	c := &canonical{template: p.GetTemplate(), fields: map[string]*pb.Field{}}
	placed := map[string]instance{}

	switch {
	case p.GetSaml2() != nil:
		layout := cmp.Or(proto.CloneOf(p.GetSaml2().GetLayout()), &pb.SAML2Layout{})
		layout.Attributes = slices.DeleteFunc(layout.GetAttributes(), func(a *pb.SAML2AttributeLayout) bool {
			return placeSAML2(t, a, placed)
		})
		c.binding, c.layout = p.GetSaml2().GetSpMetadata(), layout
	default:
		layout := cmp.Or(proto.CloneOf(p.GetOidc().GetLayout()), &pb.OIDCLayout{})
		layout.Claims = slices.DeleteFunc(layout.GetClaims(), func(cl *pb.OIDCClaimLayout) bool {
			return placeOIDC(t, cl, placed)
		})
		c.binding, c.layout = &pb.OIDCCreateApp{KeyId: p.GetOidc().GetKeyId()}, layout
	}

	for _, f := range p.GetFields() {
		f = normalized(f)

		in, ok := placed[f.GetName()]
		if !ok {
			c.fields[f.GetName()] = f

			continue
		}

		f.Name = ""
		in.value = f
		c.instances = append(c.instances, in)
	}

	slices.SortFunc(c.instances, func(a, b instance) int {
		return cmp.Or(strings.Compare(a.field, b.field), strings.Compare(a.key, b.key), bytes.Compare(marshal(a.value), marshal(b.value)))
	})

	return c
}

func marshal(f *pb.Field) []byte {
	b, _ := proto.MarshalOptions{Deterministic: true}.Marshal(f)

	return b
}

// normalized clears the label and reads a value derived at creation as the request for it.
func normalized(f *pb.Field) *pb.Field {
	f = proto.CloneOf(f)
	f.Label = ""

	if f.GetStringField().GetDerivedText() != nil {
		f.Type = &pb.Field_StringField{StringField: &pb.StringField{Source: &pb.StringField_Derived{Derived: pb.Derived_DERIVED_AT_CREATION_ID}}}
	}

	return f
}

// placeSAML2 records the attribute when it places one instance of a repeatable field, the reverse of a create's placement.
func placeSAML2(t *catalog.Template, a *pb.SAML2AttributeLayout, placed map[string]instance) bool {
	name, ok := soleField(a.GetValue())
	if !ok {
		return false
	}

	for _, e := range t.Each {
		key, found := strings.CutPrefix(a.GetName(), e.NamePrefix)
		if found && isInstanceOf(name, e.Field) {
			placed[name] = instance{field: e.Field, key: key}

			return true
		}
	}

	return false
}

// placeOIDC records the claim when it places one instance of a repeatable field.
func placeOIDC(t *catalog.Template, c *pb.OIDCClaimLayout, placed map[string]instance) bool {
	name, ok := soleField(c.GetValue())
	if !ok {
		return false
	}

	p := c.GetPath()

	for _, e := range t.Each {
		if len(p) == len(e.PathPrefix)+1 && slices.Equal(p[:len(e.PathPrefix)], e.PathPrefix) && c.GetWrapInList() == e.WrapInList && isInstanceOf(name, e.Field) {
			placed[name] = instance{field: e.Field, key: p[len(p)-1]}

			return true
		}
	}

	return false
}

func soleField(e *pb.Expr) (string, bool) {
	if len(e.GetParts()) != 1 || e.GetParts()[0].GetField() == nil {
		return "", false
	}

	return e.GetParts()[0].GetField().GetName(), true
}

// isInstanceOf reports whether name is an instance name of the repeatable field: the field's name and a count.
func isInstanceOf(name, field string) bool {
	n, ok := strings.CutPrefix(name, field+"_")

	return ok && n != "" && strings.Trim(n, "0123456789") == ""
}

// rebuiltInputs are the block inputs a record holds, as config writes them.
type rebuiltInputs struct {
	saml2  types.List
	oidc   types.List
	fields types.List
	nameID types.List
}

// inputsFromRecord rebuilds the binding, field and name_id blocks from a record. It leaves out each field the template fills
// itself and a NameID the template gives by default, and refuses a value the schema cannot express.
func inputsFromRecord(ctx context.Context, t *catalog.Template, app *pb.ConnectedAppParams) (*rebuiltInputs, error) {
	saml2, oidc, err := bindingFromRecord(ctx, app)
	if err != nil {
		return nil, err
	}

	create, err := recordAsCreate(app)
	if err != nil {
		return nil, err
	}

	placed := map[string]instance{}
	canonicalPlacement(t, create, placed)

	models := make([]fieldModel, 0, len(app.GetFields()))

	for _, f := range app.GetFields() {
		fm, keep, err := fieldFromRecord(t, f, placed)
		if err != nil {
			return nil, err
		}

		if keep {
			models = append(models, fm)
		}
	}

	fields, diags := types.ListValueFrom(ctx, fieldType(), models)
	if diags.HasError() {
		return nil, fmt.Errorf("%w: building fields", errUnexpressible)
	}

	nameID, err := nameIDFromLayout(ctx, app.GetSaml2().GetLayout().GetNameId().GetValue())
	if err != nil {
		return nil, err
	}

	return &rebuiltInputs{saml2: saml2, oidc: oidc, fields: fields, nameID: nameID}, nil
}

// canonicalPlacement fills placed with the instances the create's layout places.
func canonicalPlacement(t *catalog.Template, create *pb.CreateAppParams, placed map[string]instance) {
	for _, a := range create.GetSaml2().GetLayout().GetAttributes() {
		placeSAML2(t, a, placed)
	}

	for _, c := range create.GetOidc().GetLayout().GetClaims() {
		placeOIDC(t, c, placed)
	}
}

func bindingFromRecord(ctx context.Context, app *pb.ConnectedAppParams) (types.List, types.List, error) {
	saml2 := []saml2Model{}
	oidc := []oidcModel{}

	if b := app.GetSaml2().GetBinding(); app.GetSaml2() != nil {
		m, err := saml2FromMetadata(b)
		if err != nil {
			return types.List{}, types.List{}, err
		}

		saml2 = append(saml2, m)
	}

	if b := app.GetOidc().GetBinding(); app.GetOidc() != nil {
		oidc = append(oidc, oidcModel{KeyID: types.StringValue(base64.StdEncoding.EncodeToString(b.GetKeyId()))})
	}

	saml2List, d1 := types.ListValueFrom(ctx, saml2Type(), saml2)
	oidcList, d2 := types.ListValueFrom(ctx, oidcType(), oidc)

	if d1.HasError() || d2.HasError() {
		return types.List{}, types.List{}, fmt.Errorf("%w: building the binding", errUnexpressible)
	}

	return saml2List, oidcList, nil
}

// saml2FromMetadata writes the SP metadata as entity_id and acs_url when that is all it holds, else as metadata_xml.
func saml2FromMetadata(b *pb.SAML2Binding) (saml2Model, error) {
	md := b.GetSpMetadata()
	ed := md.GetEntityDescriptor()

	acs := ""
	if sps := ed.GetSpSsoDescriptor(); len(sps) > 0 && len(sps[0].GetAssertionConsumerService()) > 0 {
		acs = sps[0].GetAssertionConsumerService()[0].GetBase().GetLocation()
	}

	if proto.Equal(md, catalog.MinimalSPMetadata(ed.GetEntityId(), acs)) {
		return saml2Model{EntityID: types.StringValue(ed.GetEntityId()), ACSURL: types.StringValue(acs), MetadataXML: types.StringNull()}, nil
	}

	xmlText, err := renderMetadata(md)
	if err != nil {
		return saml2Model{}, fmt.Errorf("%w: %w", errUnexpressible, err)
	}

	return saml2Model{EntityID: types.StringNull(), ACSURL: types.StringNull(), MetadataXML: types.StringValue(xmlText)}, nil
}

// fieldFromRecord returns the field block of one record field, and false for a field the template fills itself.
func fieldFromRecord(t *catalog.Template, f *pb.Field, placed map[string]instance) (fieldModel, bool, error) {
	fm := emptyFieldModel(f.GetName())

	if in, ok := placed[f.GetName()]; ok {
		fm.Name, fm.Key = types.StringValue(in.field), types.StringValue(in.key)
	} else {
		spec, ok := t.Spec(f.GetName())
		if !ok {
			return fm, false, fmt.Errorf("%w: field %q is not a field of the %s template", errUnexpressible, f.GetName(), t.Name)
		}

		if implicit := catalog.ImplicitField(spec); implicit != nil && proto.Equal(normalized(implicit), normalized(f)) {
			return fm, false, nil
		}
	}

	err := fm.setSource(f)
	if err != nil {
		return fm, false, fmt.Errorf("%w: field %q: %w", errUnexpressible, f.GetName(), err)
	}

	return fm, true, nil
}

var (
	errNoSource     = errors.New("it has no source")
	errSubSecond    = errors.New("a duration has a fraction of a second")
	errRequesterCut = errors.New("its requester constraint has a prefix or a maximum length")
	errJSONNull     = errors.New("its JSON object holds a null")
)

func emptyFieldModel(name string) fieldModel {
	null := types.StringNull()
	nullList := types.ListNull(types.StringType)

	return fieldModel{
		Name: types.StringValue(name), Key: null, Value: null, Values: nullList, Seconds: types.Int64Null(),
		DurationRange: types.ListValueMust(durationRangeType(), []attr.Value{}),
		Choices:       nullList, DefaultValue: null, DefaultValues: nullList,
		Affix:     types.ListValueMust(affixType(), []attr.Value{}),
		Requester: null, Suffix: null, Derived: null, JSON: null,
	}
}

func (fm *fieldModel) setSource(f *pb.Field) error {
	switch t := f.GetType().(type) {
	case *pb.Field_StringField:
		return fm.setString(t.StringField)
	case *pb.Field_StringListField:
		return fm.setList(t.StringListField)
	case *pb.Field_DurationField:
		return fm.setDuration(t.DurationField)
	case *pb.Field_JsonObjectField:
		text, err := jsonText(t.JsonObjectField.GetFixed())
		if err != nil {
			return err
		}

		fm.JSON = types.StringValue(text)

		return nil
	}

	return errNoSource
}

func (fm *fieldModel) setString(s *pb.StringField) error {
	switch src := s.GetSource().(type) {
	case *pb.StringField_Fixed:
		fm.Value = types.StringValue(src.Fixed.GetValue())
	case *pb.StringField_Modifiable:
		return fm.setModifiableString(src.Modifiable)
	case *pb.StringField_Derived:
		return fm.setDerived(src.Derived)
	case *pb.StringField_DerivedText:
		fm.Derived = types.StringValue(derivedAtCreation)
	case *pb.StringField_Requester:
		return fm.setRequester(src.Requester)
	default:
		return errNoSource
	}

	return nil
}

func (fm *fieldModel) setModifiableString(m *pb.StringModifiable) error {
	if d := m.GetDefaultValue(); d != nil {
		fm.DefaultValue = types.StringValue(d.GetValue())
	}

	switch c := m.GetConstraint().(type) {
	case *pb.StringModifiable_Choices:
		fm.Choices = stringList(c.Choices.GetValues())
	case *pb.StringModifiable_Affix:
		fm.Affix = types.ListValueMust(affixType(), []attr.Value{affixObject(c.Affix)})
	default:
		return errNoSource
	}

	return nil
}

func (fm *fieldModel) setDerived(d pb.Derived) error {
	switch d {
	case pb.Derived_DERIVED_PER_SIGN_IN_ID:
		fm.Derived = types.StringValue(derivedPerSignIn)
	case pb.Derived_DERIVED_AT_CREATION_ID:
		fm.Derived = types.StringValue(derivedAtCreation)
	case pb.Derived_DERIVED_UNSPECIFIED:
		return errNoSource
	default:
		return errNoSource
	}

	return nil
}

func (fm *fieldModel) setRequester(r *pb.RequesterSource) error {
	switch r.GetKind() {
	case pb.Requester_REQUESTER_EMAIL:
		fm.Requester = types.StringValue(requesterEmail)
	case pb.Requester_REQUESTER_SESSION_NAME:
		fm.Requester = types.StringValue(requesterSessionName)
	case pb.Requester_REQUESTER_UNSPECIFIED:
		return errNoSource
	default:
		return errNoSource
	}

	c := r.GetConstraint()
	if c.GetPrefix() != "" || c.GetMaxLength() != 0 {
		return errRequesterCut
	}

	if c.GetSuffix() != "" {
		fm.Suffix = types.StringValue(c.GetSuffix())
	}

	return nil
}

func (fm *fieldModel) setList(l *pb.StringListField) error {
	switch src := l.GetSource().(type) {
	case *pb.StringListField_Fixed:
		fm.Values = stringList(src.Fixed.GetValues())
	case *pb.StringListField_Modifiable:
		fm.Choices = stringList(src.Modifiable.GetChoices().GetValues())
		if d := src.Modifiable.GetDefaultValue(); d != nil {
			fm.DefaultValues = stringList(d.GetValues())
		}
	default:
		return errNoSource
	}

	return nil
}

func (fm *fieldModel) setDuration(d *pb.DurationField) error {
	switch src := d.GetSource().(type) {
	case *pb.DurationField_Fixed:
		v := src.Fixed.GetValue()
		if v.GetNanos() != 0 {
			return errSubSecond
		}

		fm.Seconds = types.Int64Value(v.GetSeconds())
	case *pb.DurationField_Modifiable:
		r := src.Modifiable.GetRange()
		if r == nil || r.GetMin().GetNanos() != 0 || r.GetMax().GetNanos() != 0 || src.Modifiable.GetDefaultValue().GetValue().GetNanos() != 0 {
			return errSubSecond
		}

		def := types.Int64Null()
		if dv := src.Modifiable.GetDefaultValue(); dv != nil {
			def = types.Int64Value(dv.GetValue().GetSeconds())
		}

		fm.DurationRange = types.ListValueMust(durationRangeType(), []attr.Value{types.ObjectValueMust(durationRangeType().AttrTypes, map[string]attr.Value{
			"min_seconds": types.Int64Value(r.GetMin().GetSeconds()), "max_seconds": types.Int64Value(r.GetMax().GetSeconds()), "default_seconds": def,
		})})
	default:
		return errNoSource
	}

	return nil
}

func stringList(values []string) types.List {
	elems := make([]attr.Value, len(values))
	for i, v := range values {
		elems[i] = types.StringValue(v)
	}

	return types.ListValueMust(types.StringType, elems)
}

func affixObject(a *pb.StringAffix) attr.Value {
	text := func(s string) types.String {
		if s == "" {
			return types.StringNull()
		}

		return types.StringValue(s)
	}

	maxLength := types.Int64Null()
	if a.GetMaxLength() != 0 {
		maxLength = types.Int64Value(int64(a.GetMaxLength()))
	}

	return types.ObjectValueMust(affixType().AttrTypes, map[string]attr.Value{
		"prefix": text(a.GetPrefix()), "suffix": text(a.GetSuffix()), "max_length": maxLength,
	})
}

// jsonText writes a JSON object with its members in order.
func jsonText(obj *pb.JsonObjectValue) (string, error) {
	var b strings.Builder

	err := writeJSONObject(&b, obj)

	return b.String(), err
}

func writeJSONObject(b *strings.Builder, obj *pb.JsonObjectValue) error {
	b.WriteByte('{')

	for i, m := range obj.GetMembers() {
		if i > 0 {
			b.WriteByte(',')
		}

		err := writeJSONString(b, m.GetName())
		if err != nil {
			return err
		}

		b.WriteByte(':')

		err = writeJSONValue(b, m.GetValue())
		if err != nil {
			return err
		}
	}

	b.WriteByte('}')

	return nil
}

func writeJSONValue(b *strings.Builder, v *pb.JsonObjectValue_Value) error {
	switch k := v.GetKind().(type) {
	case *pb.JsonObjectValue_Value_StringValue:
		return writeJSONString(b, k.StringValue)
	case *pb.JsonObjectValue_Value_IntegerValue:
		b.WriteString(strconv.FormatInt(k.IntegerValue, 10))
	case *pb.JsonObjectValue_Value_BooleanValue:
		b.WriteString(strconv.FormatBool(k.BooleanValue))
	case *pb.JsonObjectValue_Value_ObjectValue:
		return writeJSONObject(b, k.ObjectValue)
	case *pb.JsonObjectValue_Value_ListValue:
		b.WriteByte('[')

		for i, item := range k.ListValue.GetValues() {
			if i > 0 {
				b.WriteByte(',')
			}

			err := writeJSONValue(b, item)
			if err != nil {
				return err
			}
		}

		b.WriteByte(']')
	default:
		return errJSONNull
	}

	return nil
}

func writeJSONString(b *strings.Builder, s string) error {
	quoted, err := json.Marshal(s)
	if err != nil {
		return fmt.Errorf("writing a JSON string: %w", err)
	}

	b.Write(quoted)

	return nil
}

// nameIDFromLayout returns the name_id block for a NameID other than the template's default, the bare name_id field.
func nameIDFromLayout(ctx context.Context, e *pb.Expr) (types.List, error) {
	if name, ok := soleField(e); ok && name == "name_id" || e == nil {
		return types.ListValueMust(nameIDType(), []attr.Value{}), nil
	}

	parts := make([]string, 0, len(e.GetParts()))

	for _, p := range e.GetParts() {
		switch {
		case p.GetField() != nil:
			parts = append(parts, fieldPartPrefix+p.GetField().GetName())
		case strings.HasPrefix(p.GetText(), fieldPartPrefix):
			return types.List{}, fmt.Errorf("%w: the NameID text %q reads as a field part", errUnexpressible, p.GetText())
		case p.GetDurationSeconds() != nil:
			return types.List{}, fmt.Errorf("%w: the NameID holds a duration", errUnexpressible)
		default:
			parts = append(parts, p.GetText())
		}
	}

	out, diags := types.ListValueFrom(ctx, nameIDType(), []nameIDModel{{Parts: stringList(parts)}})
	if diags.HasError() {
		return types.List{}, fmt.Errorf("%w: building the NameID", errUnexpressible)
	}

	return out, nil
}
