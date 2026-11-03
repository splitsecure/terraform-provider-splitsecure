// Package connectedapp builds the create request for a connected app from a
// catalog template: the template's fields, layout and instance placement.
package connectedapp

import (
	_ "embed"
	"encoding/json"
	"errors"
	"fmt"
	"slices"
	"sync"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	"google.golang.org/protobuf/encoding/protojson"
)

// ErrUnknownTemplate is returned for a template name the catalog does not hold.
var ErrUnknownTemplate = errors.New("connected app template is not in the catalog")

var errCatalog = errors.New("invalid template catalog")

//go:embed templates.json
var builtinTemplatesJSON []byte

//go:embed vendor-templates.json
var vendorTemplatesJSON []byte

// Protocol is what an app signs in with.
type Protocol string

// The protocols a template signs in with.
const (
	ProtocolSAML2 Protocol = "saml2"
	ProtocolOIDC  Protocol = "oidc"
)

// FieldType is a field's value type, the arm of Field.type.
type FieldType string

// The field types a spec names.
const (
	TypeString     FieldType = "string"
	TypeStringList FieldType = "stringList"
	TypeDuration   FieldType = "duration"
	TypeJSONObject FieldType = "jsonObject"
)

// Source is where a field's value comes from, the arm of its source oneof.
type Source string

// The sources a spec may allow.
const (
	SourceFixed             Source = "fixed"
	SourceModifiable        Source = "modifiable"
	SourceDerivedAtCreation Source = "derivedAtCreation"
	SourceDerivedPerSignIn  Source = "derivedPerSignIn"
	SourceRequester         Source = "requester"
)

// FieldSpec is a template's definition of one field.
type FieldSpec struct {
	Name  string    `json:"name"`
	Label string    `json:"label"`
	Type  FieldType `json:"type"`
	// Repeatable fields are given as instances, each under its own key.
	Repeatable bool `json:"repeatable"`
	// Required fields must be in a create; a repeatable one at least once.
	Required bool     `json:"required"`
	Sources  []Source `json:"sources"`
	// Requesters are the Requester enum names a requester source may take.
	Requesters []string `json:"requesters"`
	// Choices, when set, are the only values a fixed text may take.
	Choices    []string `json:"choices"`
	MinSeconds int64    `json:"minSeconds"`
	MaxSeconds int64    `json:"maxSeconds"`
}

// Each places every instance of a repeatable field: a SAML2 attribute named
// NamePrefix plus the instance's key, or a claim at PathPrefix plus the key.
type Each struct {
	Field      string   `json:"field"`
	NamePrefix string   `json:"namePrefix"`
	PathPrefix []string `json:"pathPrefix"`
	// WrapInList carries a text claim as a one-item list.
	WrapInList bool `json:"wrapInList"`
}

// Template is one catalog template: the fields a create fills and the layout
// it copies into the record. Callers must not modify it.
type Template struct {
	Name        string      `json:"name"`
	Title       string      `json:"title"`
	Protocol    Protocol    `json:"protocol"`
	SigningAlgs []string    `json:"signingAlgs"`
	Fields      []FieldSpec `json:"fields"`
	// Layout is the protobuf JSON of the SAML2Layout or OIDCLayout.
	Layout json.RawMessage `json:"layout"`
	Each   []Each          `json:"each"`

	saml2Layout *pb.SAML2Layout
	oidcLayout  *pb.OIDCLayout
}

// Spec returns the template's spec for the field name.
func (t *Template) Spec(name string) (*FieldSpec, bool) {
	for i := range t.Fields {
		if t.Fields[i].Name == name {
			return &t.Fields[i], true
		}
	}

	return nil, false
}

func (t *Template) each(field string) (Each, bool) {
	for _, e := range t.Each {
		if e.Field == field {
			return e, true
		}
	}

	return Each{}, false
}

type templateFile struct {
	Templates []*Template `json:"templates"`
}

//nolint:gochecknoglobals // the embedded catalog is parsed once, on first use
var catalog = sync.OnceValue(func() map[string]*Template {
	out, err := parseCatalog(builtinTemplatesJSON, vendorTemplatesJSON)
	if err != nil {
		panic(err)
	}

	return out
})

func parseCatalog(files ...[]byte) (map[string]*Template, error) {
	out := map[string]*Template{}

	for _, data := range files {
		var file templateFile

		err := json.Unmarshal(data, &file)
		if err != nil {
			return nil, fmt.Errorf("%w: %w", errCatalog, err)
		}

		for _, t := range file.Templates {
			if _, dup := out[t.Name]; dup {
				return nil, fmt.Errorf("%w: template %q appears twice", errCatalog, t.Name)
			}

			err := t.parseLayout()
			if err != nil {
				return nil, err
			}

			out[t.Name] = t
		}
	}

	return out, nil
}

func (t *Template) parseLayout() error {
	opts := protojson.UnmarshalOptions{}

	switch t.Protocol {
	case ProtocolSAML2:
		t.saml2Layout = &pb.SAML2Layout{}

		err := opts.Unmarshal(t.Layout, t.saml2Layout)
		if err != nil {
			return fmt.Errorf("%w: the %s layout: %w", errCatalog, t.Name, err)
		}
	case ProtocolOIDC:
		t.oidcLayout = &pb.OIDCLayout{}

		err := opts.Unmarshal(t.Layout, t.oidcLayout)
		if err != nil {
			return fmt.Errorf("%w: the %s layout: %w", errCatalog, t.Name, err)
		}
	default:
		return fmt.Errorf("%w: template %q has protocol %q", errCatalog, t.Name, t.Protocol)
	}

	return nil
}

// Lookup returns the catalog template named name.
func Lookup(name string) (*Template, error) {
	t, ok := catalog()[name]
	if !ok {
		return nil, fmt.Errorf("%w: %q", ErrUnknownTemplate, name)
	}

	return t, nil
}

// Names returns every catalog template's name, sorted.
func Names() []string {
	out := make([]string, 0, len(catalog()))
	for name := range catalog() {
		out = append(out, name)
	}

	slices.Sort(out)

	return out
}
