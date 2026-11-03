package connectedapp

import (
	"errors"
	"slices"
	"testing"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/reflect/protoreflect"
)

func TestNamesListsBuiltInAndVendorTemplates(t *testing.T) {
	want := []string{
		"oidc/aws", "oidc/azure", "oidc/gcp", "oidc/generic",
		"saml2/aws", "saml2/cloudflare", "saml2/gcp", "saml2/generic", "saml2/google-workspace",
		"saml2/google-workspace-legacy", "saml2/iru", "saml2/microsoft-entra-id", "saml2/okta",
		"saml2/oracle-cloud", "saml2/pagerduty", "saml2/rapid7",
	}

	if got := Names(); !slices.Equal(got, want) {
		t.Errorf("Names() = %v, want %v", got, want)
	}

	for _, name := range want {
		tmpl, err := Lookup(name)
		if err != nil {
			t.Fatal(err)
		}

		if tmpl.Title == "" {
			t.Errorf("template %s has no title", name)
		}
	}
}

func TestSpecsStateEachFieldAsTheRegistryDoes(t *testing.T) {
	spec := mustSpec(t, "saml2/aws", "session_duration")
	if spec.Type != TypeDuration || !slices.Equal(spec.Sources, []Source{SourceFixed, SourceModifiable}) || spec.MinSeconds != 900 || spec.MaxSeconds != 43200 {
		t.Errorf("saml2/aws session_duration = %+v", spec)
	}

	if !slices.Contains(mustSpec(t, "saml2/generic", "name_id_format").Choices, "urn:oasis:names:tc:SAML:2.0:nameid-format:transient") {
		t.Error("saml2/generic name_id_format lacks the transient format")
	}

	if !slices.Contains(mustSpec(t, "saml2/pagerduty", "role").Choices, "observer") {
		t.Error("saml2/pagerduty role lacks observer")
	}

	_, err := Lookup("saml2/unknown")
	if !errors.Is(err, ErrUnknownTemplate) {
		t.Errorf("Lookup(saml2/unknown) error = %v, want ErrUnknownTemplate", err)
	}
}

func mustSpec(t *testing.T, template, field string) *FieldSpec {
	t.Helper()

	tmpl, err := Lookup(template)
	if err != nil {
		t.Fatal(err)
	}

	spec, ok := tmpl.Spec(field)
	if !ok {
		t.Fatalf("template %s has no field %s", template, field)
	}

	return spec
}

func TestEveryTemplateBuildsWithMinimalFields(t *testing.T) {
	for _, name := range Names() {
		t.Run(name, func(t *testing.T) {
			tmpl, err := Lookup(name)
			if err != nil {
				t.Fatal(err)
			}

			binding := Binding{OIDCKeyID: []byte{1}}
			if tmpl.Protocol == ProtocolSAML2 {
				binding = Binding{SAML2: MinimalSPMetadata("https://sp.example", "https://sp.example/acs")}
			}

			fields, instances := minimalInputs(t, tmpl)

			params, err := Build(name, binding, fields, instances)
			if err != nil {
				t.Fatal(err)
			}

			assertBuiltFrom(t, tmpl, params)
		})
	}
}

func assertBuiltFrom(t *testing.T, tmpl *Template, params *pb.CreateAppParams) {
	t.Helper()

	if params.GetTemplate() != tmpl.Name || params.GetTitle() != tmpl.Title {
		t.Errorf("template, title = %q, %q", params.GetTemplate(), params.GetTitle())
	}

	for _, f := range params.GetFields() {
		if f.GetLabel() == "" {
			t.Errorf("field %s has no label", f.GetName())
		}
	}

	if params.GetSaml2().GetLayout() == nil && params.GetOidc().GetLayout() == nil {
		t.Error("params carry no layout")
	}
}

// minimalInputs returns a field or an instance for every required field the
// template does not fill itself.
func minimalInputs(t *testing.T, tmpl *Template) ([]*pb.Field, []Instance) {
	t.Helper()

	var (
		fields    []*pb.Field
		instances []Instance
	)

	for i := range tmpl.Fields {
		spec := &tmpl.Fields[i]
		if !spec.Required || spec.implicitField() != nil {
			continue
		}

		f := minimalField(t, spec)
		if spec.Repeatable {
			instances = append(instances, Instance{Key: "k", Field: f})

			continue
		}

		fields = append(fields, f)
	}

	return fields, instances
}

// minimalField returns a valid field of the spec's type from a source the
// admin supplies.
func minimalField(t *testing.T, spec *FieldSpec) *pb.Field {
	t.Helper()

	if !slices.Contains(spec.Sources, SourceFixed) {
		t.Fatalf("field %s has no fixed source", spec.Name)
	}

	switch spec.Type {
	case TypeString:
		value := "x"
		if len(spec.Choices) > 0 {
			value = spec.Choices[0]
		}

		return FixedString(spec.Name, value)
	case TypeStringList:
		return FixedStringList(spec.Name, []string{"x"})
	case TypeDuration:
		return FixedDuration(spec.Name, max(spec.MinSeconds, 60))
	case TypeJSONObject:
		return mustJSON(t, spec.Name, []Member{{"k", "v"}})
	}

	t.Fatalf("field %s has type %q", spec.Name, spec.Type)

	return nil
}

func TestEveryLayoutReferencesOnlyDeclaredFields(t *testing.T) {
	for _, name := range Names() {
		tmpl, err := Lookup(name)
		if err != nil {
			t.Fatal(err)
		}

		var layout proto.Message = tmpl.oidcLayout
		if tmpl.Protocol == ProtocolSAML2 {
			layout = tmpl.saml2Layout
		}

		refs := fieldRefs(layout.ProtoReflect())
		if len(refs) == 0 {
			t.Errorf("template %s layout references no field", name)
		}

		for _, e := range tmpl.Each {
			refs = append(refs, e.Field)
		}

		for _, ref := range refs {
			if _, ok := tmpl.Spec(ref); !ok {
				t.Errorf("template %s references undeclared field %s", name, ref)
			}
		}
	}
}

// fieldRefs returns the name of every FieldRef in m, at any depth.
func fieldRefs(m protoreflect.Message) []string {
	if ref, ok := m.Interface().(*pb.FieldRef); ok {
		return []string{ref.GetName()}
	}

	var out []string

	m.Range(func(fd protoreflect.FieldDescriptor, v protoreflect.Value) bool {
		if fd.Kind() != protoreflect.MessageKind {
			return true
		}

		if fd.IsList() {
			for i := range v.List().Len() {
				out = append(out, fieldRefs(v.List().Get(i).Message())...)
			}

			return true
		}

		if !fd.IsMap() {
			out = append(out, fieldRefs(v.Message())...)
		}

		return true
	})

	return out
}
