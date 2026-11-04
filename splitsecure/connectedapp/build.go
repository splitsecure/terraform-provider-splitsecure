package connectedapp

import (
	"errors"
	"fmt"
	"slices"
	"strconv"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	samlv2 "github.com/splitsecure/apis/gen/go/proto/splitsecure/oasis/saml/v2"
	"google.golang.org/protobuf/proto"
)

var (
	// ErrBinding is returned when the binding does not match the template's protocol.
	ErrBinding = errors.New("binding does not match the template")
	// ErrUnknownField is returned for a field the template does not define.
	ErrUnknownField = errors.New("template has no such field")
	// ErrInstanceOnly is returned for a repeatable field given as a field.
	ErrInstanceOnly = errors.New("template takes the field as instances")
	// ErrNotRepeatable is returned for an instance of a field that is not repeatable.
	ErrNotRepeatable = errors.New("template has no such repeatable field")
	// ErrRequired is returned when a required field is missing.
	ErrRequired = errors.New("template requires the field")
	// ErrFieldType is returned for a field whose type is not the spec's.
	ErrFieldType = errors.New("field has the wrong type")
	// ErrSource is returned for a field whose source the spec does not allow.
	ErrSource = errors.New("field source is not allowed")
	// ErrValue is returned for a value outside the spec's choices or bounds.
	ErrValue = errors.New("field value is not allowed")
	// ErrNameID is returned for a NameID given to a template without one.
	ErrNameID = errors.New("template has no NameID")
)

const fieldNameID = "name_id"

// Binding is what a create binds the app to: the SP's metadata for a SAML2
// template, or the issuer key id a token is signed with for an OIDC one.
// Exactly one is set.
type Binding struct {
	SAML2     *samlv2.Metadata
	OIDCKeyID []byte
}

// Instance is one instance of a repeatable field: the key its layout entry
// carries it under, such as a session tag key or a claim name, and the field
// named after its spec.
type Instance struct {
	Key   string
	Field *pb.Field
}

// Option adjusts a Build.
type Option func(*buildOptions)

type buildOptions struct {
	nameID []*pb.ExprPart
}

// WithNameID replaces a SAML2 layout's NameID value, wherever the layout
// places the name_id field alone, with parts.
func WithNameID(parts ...*pb.ExprPart) Option {
	return func(o *buildOptions) { o.nameID = parts }
}

// TextPart returns a layout expression part holding literal text.
func TextPart(s string) *pb.ExprPart {
	return &pb.ExprPart{Part: &pb.ExprPart_Text{Text: s}}
}

// FieldPart returns a layout expression part holding a field's value.
func FieldPart(name string) *pb.ExprPart {
	return &pb.ExprPart{Part: &pb.ExprPart_Field{Field: &pb.FieldRef{Name: name}}}
}

// InstanceName is the name a create gives the nth instance of a repeatable
// field, from 1.
func InstanceName(field string, n int) string {
	return field + "_" + strconv.Itoa(n)
}

// Build returns the create params for the catalog template name: the given
// fields and instances labelled from their specs, each instance renamed and
// placed where the template's each puts it, the required fields the template
// fills itself, and the template's layout less the entries that use an
// optional field left unset. Inputs are not modified.
func Build(name string, binding Binding, fields []*pb.Field, instances []Instance, opts ...Option) (*pb.CreateAppParams, error) {
	t, err := Lookup(name)
	if err != nil {
		return nil, err
	}

	var o buildOptions
	for _, opt := range opts {
		opt(&o)
	}

	return t.build(binding, fields, instances, o)
}

func (t *Template) build(binding Binding, fields []*pb.Field, instances []Instance, o buildOptions) (*pb.CreateAppParams, error) {
	err := t.checkBinding(binding, o)
	if err != nil {
		return nil, err
	}

	given, err := t.labelFields(fields)
	if err != nil {
		return nil, err
	}

	placed, err := t.placeInstances(instances)
	if err != nil {
		return nil, err
	}

	implicit, err := t.implicitFields(given, placed)
	if err != nil {
		return nil, err
	}

	all := slices.Concat(given, placed.fields, implicit)
	params := &pb.CreateAppParams{Template: t.Name, Title: t.Title, Fields: all}

	if binding.SAML2 != nil {
		layout := t.saml2LayoutFor(all, placed.attributes, o.nameID)

		// The NameID stays in the layout whatever it uses, and the enclave refuses one that uses a field the app lacks.
		if nameID := layout.GetNameId(); !usesOnly(nameID.GetFormat(), all) || !usesOnly(nameID.GetValue(), all) {
			return nil, fmt.Errorf("%w: the %s template's NameID uses a field the app does not carry; set %s or give a NameID", ErrRequired, t.Name, fieldNameID)
		}

		params.App = &pb.CreateAppParams_Saml2{Saml2: &pb.SAML2CreateApp{SpMetadata: proto.CloneOf(binding.SAML2), Layout: layout}}

		return params, nil
	}

	params.App = &pb.CreateAppParams_Oidc{Oidc: &pb.OIDCCreateApp{
		KeyId:  slices.Clone(binding.OIDCKeyID),
		Layout: t.oidcLayoutFor(all, placed.claims),
	}}

	return params, nil
}

func (t *Template) checkBinding(b Binding, o buildOptions) error {
	saml2 := b.SAML2 != nil
	oidc := len(b.OIDCKeyID) > 0

	if saml2 == oidc {
		return fmt.Errorf("%w: give exactly one of SAML2 metadata or an OIDC key id", ErrBinding)
	}

	if saml2 != (t.Protocol == ProtocolSAML2) {
		return fmt.Errorf("%w: template %s binds to a %s issuer", ErrBinding, t.Name, t.Protocol)
	}

	if o.nameID != nil && t.Protocol != ProtocolSAML2 {
		return fmt.Errorf("%w: %s", ErrNameID, t.Name)
	}

	return nil
}

// labelFields returns clones of the given fields, each checked against and
// labelled from its spec.
func (t *Template) labelFields(fields []*pb.Field) ([]*pb.Field, error) {
	out := make([]*pb.Field, 0, len(fields))

	for _, f := range fields {
		spec, ok := t.Spec(f.GetName())
		if !ok {
			return nil, fmt.Errorf("%w: the %s template has no field %s", ErrUnknownField, t.Name, f.GetName())
		}

		if spec.Repeatable {
			return nil, fmt.Errorf("%w: the %s template takes field %s as instances", ErrInstanceOnly, t.Name, f.GetName())
		}

		err := spec.check(f)
		if err != nil {
			return nil, fmt.Errorf("the %s template: %w", t.Name, err)
		}

		f = proto.CloneOf(f)
		f.Label = spec.Label
		out = append(out, f)
	}

	return out, nil
}

// placedInstances are a create's instances as the record holds them: their
// fields, the layout entries that place them, and how many each field has.
type placedInstances struct {
	fields     []*pb.Field
	attributes []*pb.SAML2AttributeLayout
	claims     []*pb.OIDCClaimLayout
	count      map[string]int
}

// placeInstances renames each instance after its field and count, labels it,
// and places it where the template's each puts it.
func (t *Template) placeInstances(instances []Instance) (*placedInstances, error) {
	out := &placedInstances{count: map[string]int{}}

	for _, in := range instances {
		name := in.Field.GetName()
		spec, ok := t.Spec(name)
		each, placed := t.each(name)

		if !ok || !spec.Repeatable || !placed {
			return nil, fmt.Errorf("%w: the %s template has no repeatable field %s", ErrNotRepeatable, t.Name, name)
		}

		err := spec.check(in.Field)
		if err != nil {
			return nil, fmt.Errorf("the %s template, instance %q: %w", t.Name, in.Key, err)
		}

		out.count[name]++
		f := proto.CloneOf(in.Field)
		f.Name = InstanceName(name, out.count[name])
		f.Label = spec.Label
		out.fields = append(out.fields, f)

		value := &pb.Expr{Parts: []*pb.ExprPart{FieldPart(f.GetName())}}
		if t.Protocol == ProtocolSAML2 {
			out.attributes = append(out.attributes, &pb.SAML2AttributeLayout{Name: each.NamePrefix + in.Key, Value: value})

			continue
		}

		path := append(slices.Clone(each.PathPrefix), in.Key)
		out.claims = append(out.claims, &pb.OIDCClaimLayout{Path: path, Value: value, WrapInList: each.WrapInList})
	}

	return out, nil
}

// implicitFields refuses a required field left out and returns those the
// template fills itself.
func (t *Template) implicitFields(given []*pb.Field, placed *placedInstances) ([]*pb.Field, error) {
	var out []*pb.Field

	for i := range t.Fields {
		spec := &t.Fields[i]

		if spec.Repeatable {
			if spec.Required && placed.count[spec.Name] == 0 {
				return nil, fmt.Errorf("%w: the %s template requires field %s at least once", ErrRequired, t.Name, spec.Name)
			}

			continue
		}

		if hasField(given, spec.Name) {
			continue
		}

		f := spec.implicitField()
		if f == nil && spec.Required {
			return nil, fmt.Errorf("%w: the %s template requires field %s", ErrRequired, t.Name, spec.Name)
		}

		if f != nil {
			out = append(out, f)
		}
	}

	return out, nil
}

// ImplicitField returns the field a create adds for s when the admin leaves it out, or nil when the admin must set it.
func ImplicitField(s *FieldSpec) *pb.Field {
	if s.Repeatable {
		return nil
	}

	return s.implicitField()
}

// implicitField returns the required field a create leaves to the template:
// one derived by the enclave or filled from the requester.
func (s *FieldSpec) implicitField() *pb.Field {
	if !s.Required || len(s.Sources) != 1 {
		return nil
	}

	var f *pb.Field

	switch s.Sources[0] {
	case SourceDerivedPerSignIn:
		f = DerivedString(s.Name, pb.Derived_DERIVED_PER_SIGN_IN_ID)
	case SourceDerivedAtCreation:
		f = DerivedString(s.Name, pb.Derived_DERIVED_AT_CREATION_ID)
	case SourceRequester:
		kind := pb.Requester_REQUESTER_SESSION_NAME
		if len(s.Requesters) > 0 && s.Requesters[0] == pb.Requester_REQUESTER_EMAIL.String() {
			kind = pb.Requester_REQUESTER_EMAIL
		}

		f = RequesterString(s.Name, kind, "")
	case SourceFixed, SourceModifiable:
		return nil
	}

	if f != nil {
		f.Label = s.Label
	}

	return f
}

func (t *Template) saml2LayoutFor(fields []*pb.Field, attributes []*pb.SAML2AttributeLayout, nameID []*pb.ExprPart) *pb.SAML2Layout {
	layout := proto.CloneOf(t.saml2Layout)

	if nameID != nil {
		if layout.GetNameId() != nil && isNameIDField(layout.GetNameId().GetValue()) {
			layout.NameId.Value = nameIDExpr(nameID)
		}

		for _, a := range layout.GetAttributes() {
			if isNameIDField(a.GetValue()) {
				a.Value = nameIDExpr(nameID)
			}
		}
	}

	layout.Attributes = slices.DeleteFunc(layout.GetAttributes(), func(a *pb.SAML2AttributeLayout) bool {
		return !usesOnly(a.GetValue(), fields)
	})
	layout.Attributes = append(layout.Attributes, attributes...)

	return layout
}

func (t *Template) oidcLayoutFor(fields []*pb.Field, claims []*pb.OIDCClaimLayout) *pb.OIDCLayout {
	layout := proto.CloneOf(t.oidcLayout)
	layout.Claims = slices.DeleteFunc(layout.GetClaims(), func(c *pb.OIDCClaimLayout) bool {
		return !usesOnly(c.GetValue(), fields)
	})
	layout.Claims = append(layout.Claims, claims...)

	return layout
}

func nameIDExpr(parts []*pb.ExprPart) *pb.Expr {
	out := &pb.Expr{Parts: make([]*pb.ExprPart, len(parts))}
	for i, p := range parts {
		out.Parts[i] = proto.CloneOf(p)
	}

	return out
}

func isNameIDField(e *pb.Expr) bool {
	parts := e.GetParts()

	return len(parts) == 1 && parts[0].GetField() != nil && parts[0].GetField().GetName() == fieldNameID
}

// usesOnly reports whether every field e uses is among fields.
func usesOnly(e *pb.Expr, fields []*pb.Field) bool {
	for _, p := range e.GetParts() {
		var ref *pb.FieldRef

		switch part := p.GetPart().(type) {
		case *pb.ExprPart_Field:
			ref = part.Field
		case *pb.ExprPart_DurationSeconds:
			ref = part.DurationSeconds
		default:
			continue
		}

		if !hasField(fields, ref.GetName()) {
			return false
		}
	}

	return true
}

func hasField(fields []*pb.Field, name string) bool {
	return slices.ContainsFunc(fields, func(f *pb.Field) bool { return f.GetName() == name })
}
