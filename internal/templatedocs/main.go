// Command templatedocs writes the docs template for the connected app templates guide, from the embedded catalog.
package main

import (
	_ "embed"
	"errors"
	"fmt"
	"log"
	"os"
	"slices"
	"strconv"
	"strings"

	"google.golang.org/protobuf/encoding/protojson"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	catalog "github.com/splitsecure/terraform-provider-splitsecure/splitsecure/connectedapp"
)

const (
	sep  = " | "
	tick = "`"
)

var errUsage = errors.New("usage: templatedocs <output file>")

//go:embed intro.md
var intro string

func main() {
	err := run(os.Args[1:])
	if err != nil {
		log.Fatal(err)
	}
}

func run(args []string) error {
	if len(args) != 1 {
		return errUsage
	}

	g, err := guide()
	if err != nil {
		return err
	}

	err = os.WriteFile(args[0], []byte(g), 0o600) //nolint:gosec // the path is the go:generate argument.
	if err != nil {
		return fmt.Errorf("writing the guide: %w", err)
	}

	return nil
}

func guide() (string, error) {
	var b strings.Builder

	b.WriteString(intro)

	for _, name := range catalog.Names() {
		t, err := catalog.Lookup(name)
		if err != nil {
			return "", fmt.Errorf("looking up %s: %w", name, err)
		}

		layout, err := layoutTable(t)
		if err != nil {
			return "", err
		}

		b.WriteString("\n### " + t.Title + "\n\n")
		b.WriteString(code(`template = "`+t.Name+`"`) + "\n\n")
		b.WriteString(layout)
		b.WriteString(fieldsTable(t))
	}

	return b.String(), nil
}

func layoutTable(t *catalog.Template) (string, error) {
	if t.Protocol == catalog.ProtocolSAML2 {
		var l pb.SAML2Layout

		err := protojson.Unmarshal(t.Layout, &l)
		if err != nil {
			return "", fmt.Errorf("decoding the %s layout: %w", t.Name, err)
		}

		return assertionTable(t, &l), nil
	}

	var l pb.OIDCLayout

	err := protojson.Unmarshal(t.Layout, &l)
	if err != nil {
		return "", fmt.Errorf("decoding the %s layout: %w", t.Name, err)
	}

	return tokenTable(t, &l), nil
}

func assertionTable(t *catalog.Template, l *pb.SAML2Layout) string {
	var b strings.Builder

	b.WriteString("| SAML assertion | Value |\n|---|---|\n")
	b.WriteString(row("Audience", samlAudience(l)))
	b.WriteString(row("NameID format", expr(l.GetNameId().GetFormat())))
	b.WriteString(row("NameID", expr(l.GetNameId().GetValue())))

	for _, a := range l.GetAttributes() {
		b.WriteString(row("Attribute "+code(a.GetName()), expr(a.GetValue())))
	}

	for _, e := range t.Each {
		b.WriteString(row("Attribute "+code(e.NamePrefix+"<key>"), "each "+code(e.Field)+" instance"))
	}

	return b.String() + "\n"
}

func samlAudience(l *pb.SAML2Layout) string {
	if fixed := l.GetAudience().GetFixed(); fixed != "" {
		return code(fixed)
	}

	return "the entity ID in the " + code("saml2") + " block"
}

func tokenTable(t *catalog.Template, l *pb.OIDCLayout) string {
	var b strings.Builder

	b.WriteString("| OIDC token | Value |\n|---|---|\n")
	b.WriteString(row("Signing algorithm", signingAlgs(t.SigningAlgs)))
	b.WriteString(row(code("sub"), expr(l.GetSubject())))
	b.WriteString(row(code("aud"), expr(l.GetAudience())))
	b.WriteString(row("Lifetime", lifetime(l.GetLifetime())))
	b.WriteString(row(code("jti"), code(l.GetTokenId().GetName())))

	if d := l.GetRequestedClientDuration(); d != nil {
		b.WriteString(row("Session asked of the cloud", code(d.GetName())+", not in the token"))
	}

	for _, c := range l.GetClaims() {
		b.WriteString(row(claimName(c.GetPath()), listed(expr(c.GetValue()), c.GetWrapInList())))
	}

	for _, e := range t.Each {
		b.WriteString(row(claimName(append(slices.Clone(e.PathPrefix), "<key>")), listed("each "+code(e.Field)+" instance", e.WrapInList)))
	}

	return b.String() + "\n"
}

func signingAlgs(algs []string) string {
	if len(algs) == 0 {
		return "any key of the issuer"
	}

	quoted := make([]string, len(algs))
	for i, a := range algs {
		quoted[i] = code(a)
	}

	return strings.Join(quoted, ", ")
}

func lifetime(l *pb.OIDCLifetime) string {
	if f := l.GetField(); f != nil {
		return code(f.GetName())
	}

	return "600 seconds, the time the client has to exchange the token"
}

func claimName(path []string) string {
	if len(path) == 0 {
		return "Top-level claims"
	}

	quoted := make([]string, len(path))
	for i, p := range path {
		quoted[i] = code(p)
	}

	return "Claim " + strings.Join(quoted, " > ")
}

func listed(value string, wrap bool) string {
	if wrap {
		return value + ", as a list"
	}

	return value
}

// expr renders a layout value as its parts joined with +.
func expr(e *pb.Expr) string {
	parts := make([]string, 0, len(e.GetParts()))

	for _, p := range e.GetParts() {
		switch {
		case p.GetField() != nil:
			parts = append(parts, code(p.GetField().GetName()))
		case p.GetDurationSeconds() != nil:
			parts = append(parts, code(p.GetDurationSeconds().GetName())+" in seconds")
		default:
			parts = append(parts, code(strconv.Quote(p.GetText())))
		}
	}

	return strings.Join(parts, " + ")
}

func fieldsTable(t *catalog.Template) string {
	var b strings.Builder

	b.WriteString("| Field | Type | Required | Sources | Notes |\n|---|---|---|---|---|\n")

	for i := range t.Fields {
		s := &t.Fields[i]
		b.WriteString("| " + code(s.Name) + sep + typeName(s.Type) + sep + required(s) + sep + sources(s) + sep + notes(s) + " |\n")
	}

	return b.String()
}

func row(part, value string) string {
	return "| " + part + sep + value + " |\n"
}

func code(s string) string {
	return tick + s + tick
}

func typeName(t catalog.FieldType) string {
	switch t {
	case catalog.TypeString:
		return "text"
	case catalog.TypeStringList:
		return "list of text"
	case catalog.TypeDuration:
		return "duration"
	case catalog.TypeJSONObject:
		return "JSON object"
	default:
		return string(t)
	}
}

func required(s *catalog.FieldSpec) string {
	switch {
	case catalog.ImplicitField(s) != nil:
		return "filled by the template"
	case s.Required && s.Repeatable:
		return "at least once"
	case s.Required:
		return "yes"
	default:
		return "no"
	}
}

func sources(s *catalog.FieldSpec) string {
	out := make([]string, 0, len(s.Sources))

	for _, src := range s.Sources {
		out = append(out, sourceHCL(s, src))
	}

	return strings.Join(out, ", ")
}

func sourceHCL(s *catalog.FieldSpec, src catalog.Source) string {
	switch src {
	case catalog.SourceFixed:
		return fixedHCL(s.Type)
	case catalog.SourceModifiable:
		if s.Type == catalog.TypeDuration {
			return code("duration_range")
		}

		return code("choices")
	case catalog.SourceDerivedAtCreation:
		return code(`derived = "at_creation"`)
	case catalog.SourceDerivedPerSignIn:
		return code(`derived = "per_sign_in"`)
	case catalog.SourceRequester:
		return requesterHCL(s.Requesters)
	default:
		return string(src)
	}
}

func fixedHCL(t catalog.FieldType) string {
	switch t {
	case catalog.TypeStringList:
		return code("values")
	case catalog.TypeDuration:
		return code("seconds")
	case catalog.TypeJSONObject:
		return code("json")
	case catalog.TypeString:
		return code("value")
	default:
		return code("value")
	}
}

func requesterHCL(kinds []string) string {
	names := map[string]string{
		pb.Requester_REQUESTER_EMAIL.String():        code(`requester = "email"`),
		pb.Requester_REQUESTER_SESSION_NAME.String(): code(`requester = "session_name"`),
	}

	out := make([]string, 0, len(kinds))
	for _, k := range kinds {
		out = append(out, names[k])
	}

	return strings.Join(out, ", ")
}

func notes(s *catalog.FieldSpec) string {
	var out []string

	if s.Repeatable {
		out = append(out, "Repeatable. Give each instance a "+code("key")+".")
	}

	if len(s.Choices) > 0 {
		quoted := make([]string, len(s.Choices))
		for i, c := range s.Choices {
			quoted[i] = code(c)
		}

		out = append(out, "One of "+strings.Join(quoted, ", ")+".")
	}

	if s.MinSeconds > 0 || s.MaxSeconds > 0 {
		out = append(out, fmt.Sprintf("From %d to %d seconds.", s.MinSeconds, s.MaxSeconds))
	}

	return strings.Join(out, " ")
}
