package connectedapp

import (
	"errors"
	"fmt"
	"slices"
	"strconv"
	"strings"

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
	// ErrNameID is returned for a NameID the template or the app cannot take.
	ErrNameID = errors.New("invalid NameID")
	// ErrDuplicate is returned for a field, or an instance key, given twice.
	ErrDuplicate = errors.New("given more than once")
	// ErrInstanceKey is returned for an instance with an empty key.
	ErrInstanceKey = errors.New("instance key is empty")
)

const (
	fieldNameID      = "name_id"
	templateSAML2AWS = "saml2/aws"
)

// FieldError is a Build error about one given field, or one instance when Instance is set.
type FieldError struct {
	Name     string
	Key      string
	Instance bool
	Err      error
}

func (e *FieldError) Error() string { return e.Err.Error() }

func (e *FieldError) Unwrap() error { return e.Err }

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
	nameID  []*pb.ExprPart
	unknown map[string]bool
}

// WithNameID replaces a SAML2 layout's NameID value, wherever the layout
// places the name_id field alone, with parts.
func WithNameID(parts ...*pb.ExprPart) Option {
	return func(o *buildOptions) { o.nameID = parts }
}

// WithUnknown names fields whose values are not known yet. Build counts them
// as set and checks only that the template declares them.
func WithUnknown(names ...string) Option {
	return func(o *buildOptions) {
		o.unknown = map[string]bool{}
		for _, n := range names {
			o.unknown[n] = true
		}
	}
}

// TextPart returns a layout expression part holding literal text.
func TextPart(s string) *pb.ExprPart {
	return &pb.ExprPart{Part: &pb.ExprPart_Text{Text: s}}
}

// FieldPart returns a layout expression part holding a field's value.
func FieldPart(name string) *pb.ExprPart {
	return &pb.ExprPart{Part: &pb.ExprPart_Field{Field: &pb.FieldRef{Name: name}}}
}

// instanceName is the name a create gives the nth instance of a repeatable
// field, from 1.
func instanceName(field string, n int) string {
	return field + "_" + strconv.Itoa(n)
}

// Build returns the create params for the catalog template name from the given fields and instances, which it does not modify.
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

	given, err := t.labelFields(fields, o)
	if err != nil {
		return nil, err
	}

	placed, err := t.placeInstances(instances)
	if err != nil {
		return nil, err
	}

	implicit, err := t.implicitFields(given, placed, o)
	if err != nil {
		return nil, err
	}

	all := slices.Concat(given, placed.fields, implicit)
	params := &pb.CreateAppParams{Template: t.Name, Title: t.Title, Fields: all}

	if binding.SAML2 != nil {
		layout := t.saml2LayoutFor(all, placed.attributes, o.nameID)

		err := t.checkNameID(layout.GetNameId(), all, o)
		if err != nil {
			return nil, err
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

	switch {
	case o.nameID != nil && t.Protocol != ProtocolSAML2:
		return fmt.Errorf("%w: the %s template has no NameID", ErrNameID, t.Name)
	case o.nameID != nil && len(o.nameID) == 0:
		return fmt.Errorf("%w: a NameID needs at least one part", ErrNameID)
	}

	return nil
}

// labelFields returns clones of the given fields, each checked against and
// labelled from its spec.
func (t *Template) labelFields(fields []*pb.Field, o buildOptions) ([]*pb.Field, error) {
	out := make([]*pb.Field, 0, len(fields))

	for name := range o.unknown {
		if _, ok := t.Spec(name); !ok {
			return nil, &FieldError{Name: name, Err: fmt.Errorf("%w: the %s template has no field %s", ErrUnknownField, t.Name, name)}
		}
	}

	for _, f := range fields {
		err := t.checkGiven(f, out)
		if err != nil {
			return nil, &FieldError{Name: f.GetName(), Err: err}
		}

		spec, _ := t.Spec(f.GetName())
		f = proto.CloneOf(f)
		f.Label = spec.Label
		out = append(out, f)
	}

	if o.nameID != nil && (hasField(out, fieldNameID) || o.unknown[fieldNameID]) {
		return nil, &FieldError{Name: fieldNameID, Err: fmt.Errorf("%w: set the %s field or a NameID, not both", ErrNameID, fieldNameID)}
	}

	return out, nil
}

// checkGiven refuses a field the template does not take as a field, or takes already.
func (t *Template) checkGiven(f *pb.Field, given []*pb.Field) error {
	spec, ok := t.Spec(f.GetName())

	switch {
	case !ok:
		return fmt.Errorf("%w: the %s template has no field %s", ErrUnknownField, t.Name, f.GetName())
	case spec.Repeatable:
		return fmt.Errorf("%w: the %s template takes field %s as instances", ErrInstanceOnly, t.Name, f.GetName())
	case hasField(given, f.GetName()):
		return fmt.Errorf("%w: field %s", ErrDuplicate, f.GetName())
	}

	err := spec.check(f)
	if err != nil {
		return fmt.Errorf("the %s template: %w", t.Name, err)
	}

	return nil
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
	placedAt := map[string]bool{}

	for _, in := range instances {
		name := in.Field.GetName()

		spec, each, err := t.checkInstance(in)
		if err != nil {
			return nil, &FieldError{Name: name, Key: in.Key, Instance: true, Err: err}
		}

		path := append(slices.Clone(each.PathPrefix), in.Key)
		at := each.NamePrefix + strings.Join(path, "\x00")

		if placedAt[at] {
			return nil, &FieldError{Name: name, Key: in.Key, Instance: true, Err: fmt.Errorf("%w: instance key %q of field %s", ErrDuplicate, in.Key, name)}
		}

		placedAt[at] = true
		out.count[name]++
		f := proto.CloneOf(in.Field)
		f.Name = instanceName(name, out.count[name])
		f.Label = spec.Label
		out.fields = append(out.fields, f)

		value := &pb.Expr{Parts: []*pb.ExprPart{FieldPart(f.GetName())}}
		if t.Protocol == ProtocolSAML2 {
			out.attributes = append(out.attributes, &pb.SAML2AttributeLayout{Name: each.NamePrefix + in.Key, Value: value})

			continue
		}

		out.claims = append(out.claims, &pb.OIDCClaimLayout{Path: path, Value: value, WrapInList: each.WrapInList})
	}

	return out, nil
}

// checkInstance refuses an instance of a field that is not repeatable, with no key, or with a value the spec does not allow.
func (t *Template) checkInstance(in Instance) (*FieldSpec, Each, error) {
	name := in.Field.GetName()
	spec, ok := t.Spec(name)
	each, placed := t.each(name)

	switch {
	case !ok || !spec.Repeatable || !placed:
		return nil, Each{}, fmt.Errorf("%w: the %s template has no repeatable field %s", ErrNotRepeatable, t.Name, name)
	case in.Key == "":
		return nil, Each{}, fmt.Errorf("%w: an instance of field %s", ErrInstanceKey, name)
	}

	err := spec.check(in.Field)
	if err != nil {
		return nil, Each{}, fmt.Errorf("the %s template, instance %q: %w", t.Name, in.Key, err)
	}

	return spec, each, nil
}

// implicitFields refuses a required field left out and returns those the
// template fills itself.
func (t *Template) implicitFields(given []*pb.Field, placed *placedInstances, o buildOptions) ([]*pb.Field, error) {
	var out []*pb.Field

	for i := range t.Fields {
		spec := &t.Fields[i]

		switch {
		case o.unknown[spec.Name]:
			continue
		case spec.Repeatable:
			if spec.Required && placed.count[spec.Name] == 0 {
				return nil, fmt.Errorf("%w: the %s template requires field %s at least once", ErrRequired, t.Name, spec.Name)
			}

			continue
		case hasField(given, spec.Name):
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
		if len(s.Requesters) == 0 {
			return nil
		}

		f = RequesterString(s.Name, pb.Requester(pb.Requester_value[s.Requesters[0]]), "")
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

// checkNameID refuses a NameID that uses a field the app lacks, which the
// enclave refuses since the NameID stays in the layout whatever it uses. AWS
// reads the NameID as saml:sub, so a sign-in may choose no part of an AWS one.
func (t *Template) checkNameID(n *pb.SAML2NameIDLayout, fields []*pb.Field, o buildOptions) error {
	for _, e := range []*pb.Expr{n.GetFormat(), n.GetValue()} {
		name := missingField(e, fields, o.unknown)

		if _, declared := t.Spec(name); name != "" && !declared {
			return fmt.Errorf("%w: the NameID uses field %s, which the %s template does not declare", ErrUnknownField, name, t.Name)
		}

		if name != "" {
			return fmt.Errorf("%w: the NameID uses field %s, which the app does not set. Set the field or give a NameID", ErrRequired, name)
		}
	}

	if t.Name != templateSAML2AWS {
		return nil
	}

	for _, f := range fields {
		uses := slices.ContainsFunc(n.GetValue().GetParts(), func(p *pb.ExprPart) bool { return p.GetField().GetName() == f.GetName() })
		if _, source := typeAndSource(f); uses && source == SourceModifiable {
			return &FieldError{Name: f.GetName(), Err: fmt.Errorf("%w: a sign-in cannot choose any part of an AWS NameID", ErrSource)}
		}
	}

	return nil
}

// usesOnly reports whether every field e uses is among fields.
func usesOnly(e *pb.Expr, fields []*pb.Field) bool {
	return missingField(e, fields, nil) == ""
}

// missingField returns the first field e uses that is neither among fields nor unknown, or "".
func missingField(e *pb.Expr, fields []*pb.Field, unknown map[string]bool) string {
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

		if !hasField(fields, ref.GetName()) && !unknown[ref.GetName()] {
			return ref.GetName()
		}
	}

	return ""
}

func hasField(fields []*pb.Field, name string) bool {
	return slices.ContainsFunc(fields, func(f *pb.Field) bool { return f.GetName() == name })
}
