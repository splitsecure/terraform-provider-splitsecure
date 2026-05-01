package saml2

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
)

func TestParseResourceS2R(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		input     string
		wantOK    bool
		wantParts resourceS2RParts
	}{
		{
			name:   "well-formed saml2idp",
			input:  "s2r:us:saml2idp:9PwZ/iA4cep",
			wantOK: true,
			wantParts: resourceS2RParts{
				Deployment: "us",
				Kind:       "saml2idp",
				TeamID:     "9PwZ",
				ResourceID: "iA4cep",
			},
		},
		{
			name:   "well-formed saml2sp",
			input:  "s2r:local-kerby:saml2sp:bKwgAP3G/IpOi5fNk",
			wantOK: true,
			wantParts: resourceS2RParts{
				Deployment: "local-kerby",
				Kind:       "saml2sp",
				TeamID:     "bKwgAP3G",
				ResourceID: "IpOi5fNk",
			},
		},
		{name: "wrong scheme", input: "x:us:saml2idp:t/r", wantOK: false},
		{name: "missing kind segment", input: "s2r:us:t/r", wantOK: false},
		{name: "extra segment is captured into the resource part", input: "s2r:us:saml2idp:t:r", wantOK: false},
		{name: "no slash", input: "s2r:us:saml2idp:onlyteam", wantOK: false},
		{name: "empty team", input: "s2r:us:saml2idp:/r", wantOK: false},
		{name: "empty resource", input: "s2r:us:saml2idp:t/", wantOK: false},
		{name: "empty string", input: "", wantOK: false},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, ok := parseResourceS2R(tc.input)
			if ok != tc.wantOK {
				t.Fatalf("ok = %v, want %v", ok, tc.wantOK)
			}
			if !ok {
				return
			}
			if got != tc.wantParts {
				t.Fatalf("got %+v, want %+v", got, tc.wantParts)
			}
		})
	}
}

func TestTeamS2RFromResourceS2R(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name  string
		input string
		want  string
	}{
		{"saml2idp", "s2r:us:saml2idp:9PwZ/iA4cep", "s2r:us:team:9PwZ"},
		{"saml2sp", "s2r:local-kerby:saml2sp:bKwgAP/IpOi5", "s2r:local-kerby:team:bKwgAP"},
		{"malformed", "not-an-s2r", ""},
		{"team URI itself (no slash)", "s2r:us:team:foo", ""},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			if got := teamS2RFromResourceS2R(tc.input); got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}

func TestS2RKindValidator(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		kind      string
		input     string
		wantError bool
	}{
		{"team URI matches team kind", "team", "s2r:us:team:foo", false},
		{"team URI rejected for org kind", "org", "s2r:us:team:foo", true},
		{"saml2idp resource URI matches", "saml2idp", "s2r:us:saml2idp:t/r", false},
		{"saml2idp rejected for saml2sp", "saml2sp", "s2r:us:saml2idp:t/r", true},
		{"empty rejected", "team", "", true},
		{"non-s2r rejected", "team", "https://example.com", true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			v := s2rKindValidator(tc.kind)
			req := validator.StringRequest{
				Path:        path.Root("attr"),
				ConfigValue: types.StringValue(tc.input),
			}
			resp := &validator.StringResponse{}
			v.ValidateString(context.Background(), req, resp)
			gotError := resp.Diagnostics.HasError()
			if gotError != tc.wantError {
				t.Fatalf("error=%v, want %v: %v", gotError, tc.wantError, resp.Diagnostics.Errors())
			}
		})
	}
}

func TestHTTPSURLValidator(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		input     string
		wantError bool
	}{
		{"https with host", "https://example.com", false},
		{"https with path", "https://example.com/saml/login", false},
		{"http rejected", "http://example.com", true},
		{"ftp rejected", "ftp://example.com", true},
		{"missing scheme", "example.com/saml", true},
		{"empty value passes (Optional, validator skips)", "", false},
		{"https without host", "https://", true},
	}

	v := httpsURLValidator()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := types.StringValue(tc.input)
			if tc.input == "" {
				cfg = types.StringNull()
			}
			req := validator.StringRequest{Path: path.Root("attr"), ConfigValue: cfg}
			resp := &validator.StringResponse{}
			v.ValidateString(context.Background(), req, resp)
			gotError := resp.Diagnostics.HasError()
			if gotError != tc.wantError {
				t.Fatalf("error=%v, want %v: %v", gotError, tc.wantError, resp.Diagnostics.Errors())
			}
		})
	}
}

func TestEmailValidator(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		input     string
		wantError bool
	}{
		{"valid", "user@example.com", false},
		{"valid with display name", `"User" <user@example.com>`, false},
		{"empty value passes (Optional, validator skips)", "", false},
		{"missing @", "userexample.com", true},
		{"trailing @", "user@", true},
		{"only @", "@", true},
		{"whitespace", "user @example.com", true},
	}

	v := emailValidator()
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			cfg := types.StringValue(tc.input)
			if tc.input == "" {
				cfg = types.StringNull()
			}
			req := validator.StringRequest{Path: path.Root("attr"), ConfigValue: cfg}
			resp := &validator.StringResponse{}
			v.ValidateString(context.Background(), req, resp)
			gotError := resp.Diagnostics.HasError()
			if gotError != tc.wantError {
				t.Fatalf("error=%v, want %v: %v", gotError, tc.wantError, resp.Diagnostics.Errors())
			}
		})
	}
}

// TestValidatorDescriptions catches a class of regression where a
// validator returns an empty Description -- which would surface in
// tfplugindocs as a blank validator entry on the schema page.
func TestValidatorDescriptions(t *testing.T) {
	t.Parallel()

	checks := map[string]validator.String{
		"s2r":   s2rKindValidator("team"),
		"https": httpsURLValidator(),
		"email": emailValidator(),
	}

	for name, v := range checks {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			d := v.Description(context.Background())
			if strings.TrimSpace(d) == "" {
				t.Fatalf("%s validator has empty Description", name)
			}
			if md := v.MarkdownDescription(context.Background()); strings.TrimSpace(md) == "" {
				t.Fatalf("%s validator has empty MarkdownDescription", name)
			}
		})
	}
}
