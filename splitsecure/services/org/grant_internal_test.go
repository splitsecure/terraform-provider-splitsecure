package org

import (
	"context"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	authzv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/authz/v1"
)

// grantTestSchema pulls the schema out of the grant resource by
// calling its Schema(...) method directly, avoiding framework
// plumbing.
func grantTestSchema(t *testing.T) rschema.Schema {
	t.Helper()

	resp := &resource.SchemaResponse{}
	(&grantResource{}).Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}

	return resp.Schema
}

func TestGrantSchema_RequiredAttributes(t *testing.T) {
	t.Parallel()

	s := grantTestSchema(t)

	for _, name := range []string{"resource_s2r", "grantee_s2r", "tier"} {
		attr, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("required attribute %q missing from grant schema", name)
		}
		if !attr.IsRequired() {
			t.Errorf("attribute %q should be Required", name)
		}
	}
}

// TestGrantSchema_ReplaceSemantics asserts the grant's key attributes
// force replacement while tier stays updatable in place.
func TestGrantSchema_ReplaceSemantics(t *testing.T) {
	t.Parallel()

	s := grantTestSchema(t)

	ctx := context.Background()
	for _, name := range []string{"resource_s2r", "grantee_s2r"} {
		attr, ok := s.Attributes[name].(rschema.StringAttribute)
		if !ok {
			t.Fatalf("attribute %q has wrong type: %T", name, s.Attributes[name])
		}
		if len(attr.PlanModifiers) == 0 {
			t.Fatalf("attribute %q has no plan modifiers", name)
		}
		// Not just any modifier: at least one must carry requires-replace
		// semantics (RequiresReplace's description says the resource is recreated).
		replaces := false
		for _, mod := range attr.PlanModifiers {
			if strings.Contains(strings.ToLower(mod.Description(ctx)), "recreate") {
				replaces = true
			}
		}
		if !replaces {
			t.Errorf("attribute %q should force replacement on change", name)
		}
	}

	tier, ok := s.Attributes["tier"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("tier attribute has wrong type: %T", s.Attributes["tier"])
	}
	if len(tier.PlanModifiers) != 0 {
		t.Error("tier should have no plan modifiers; it must be updatable in place")
	}
}

// TestGrantSchema_TierValidatorAcceptsTiers executes the tier validators: every
// real tier passes and an unknown value is rejected.
func TestGrantSchema_TierValidatorAcceptsTiers(t *testing.T) {
	t.Parallel()

	s := grantTestSchema(t)
	ctx := context.Background()

	tier, ok := s.Attributes["tier"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("tier attribute has wrong type: %T", s.Attributes["tier"])
	}

	validate := func(value string) diag.Diagnostics {
		var resp validator.StringResponse
		for _, v := range tier.Validators {
			v.ValidateString(ctx, validator.StringRequest{
				Path:        path.Root("tier"),
				ConfigValue: types.StringValue(value),
			}, &resp)
		}

		return resp.Diagnostics
	}

	for _, v := range tierValues() {
		if d := validate(v); d.HasError() {
			t.Errorf("tier %q should be accepted, got: %v", v, d)
		}
	}
	if d := validate("bogus-tier"); !d.HasError() {
		t.Error(`tier "bogus-tier" should be rejected`)
	}
}

func TestTierToString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		tier    authzv1.Tier
		want    string
		wantErr bool
	}{
		{name: "view", tier: authzv1.Tier_TIER_VIEW, want: "view"},
		{name: "use", tier: authzv1.Tier_TIER_USE, want: "use"},
		{name: "edit", tier: authzv1.Tier_TIER_EDIT, want: "edit"},
		{name: "errors on unspecified", tier: authzv1.Tier_TIER_UNSPECIFIED, wantErr: true},
		{name: "errors on out-of-range value", tier: authzv1.Tier(42), wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tierToString(tc.tier)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("tierToString(%v) = %q, want error", tc.tier, got)
				}

				return
			}
			if err != nil {
				t.Fatalf("tierToString(%v): %v", tc.tier, err)
			}
			if got != tc.want {
				t.Errorf("tierToString(%v) = %q, want %q", tc.tier, got, tc.want)
			}
		})
	}
}

func TestTierFromString(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		in      string
		want    authzv1.Tier
		wantErr bool
	}{
		{name: "view", in: "view", want: authzv1.Tier_TIER_VIEW},
		{name: "use", in: "use", want: authzv1.Tier_TIER_USE},
		{name: "edit", in: "edit", want: authzv1.Tier_TIER_EDIT},
		{name: "rejects empty string", in: "", wantErr: true},
		{name: "rejects wrong case", in: "VIEW", wantErr: true},
		{name: "rejects unknown value", in: "admin", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := tierFromString(tc.in)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("tierFromString(%q) = %v, want error", tc.in, got)
				}

				return
			}
			if err != nil {
				t.Fatalf("tierFromString(%q): %v", tc.in, err)
			}
			if got != tc.want {
				t.Errorf("tierFromString(%q) = %v, want %v", tc.in, got, tc.want)
			}
		})
	}
}

// TestTierRoundTrip asserts every schema-accepted tier string survives
// string -> enum -> string unchanged, so the validator list and the
// converters can't drift apart.
func TestTierRoundTrip(t *testing.T) {
	t.Parallel()

	for _, name := range tierValues() {
		tier, err := tierFromString(name)
		if err != nil {
			t.Fatalf("tierFromString(%q): %v", name, err)
		}
		back, err := tierToString(tier)
		if err != nil {
			t.Fatalf("tierToString(%v): %v", tier, err)
		}
		if back != name {
			t.Errorf("round trip of %q produced %q", name, back)
		}
	}
}

func TestParseGrantImportID(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		id           string
		wantResource string
		wantGrantee  string
		wantErr      bool
	}{
		{
			name:         "resource and grantee",
			id:           "s2r:prod:saml2idp:team1/res1,s2r:prod:user:u1",
			wantResource: "s2r:prod:saml2idp:team1/res1",
			wantGrantee:  "s2r:prod:user:u1",
		},
		{name: "rejects missing comma", id: "s2r:prod:saml2idp:team1/res1", wantErr: true},
		{name: "rejects empty string", id: "", wantErr: true},
		{name: "rejects empty resource part", id: ",s2r:prod:user:u1", wantErr: true},
		{name: "rejects empty grantee part", id: "s2r:prod:saml2idp:team1/res1,", wantErr: true},
		{name: "rejects extra comma", id: "a,b,c", wantErr: true},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotResource, gotGrantee, err := parseGrantImportID(tc.id)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("parseGrantImportID(%q) = (%q, %q), want error", tc.id, gotResource, gotGrantee)
				}

				return
			}
			if err != nil {
				t.Fatalf("parseGrantImportID(%q): %v", tc.id, err)
			}
			if gotResource != tc.wantResource || gotGrantee != tc.wantGrantee {
				t.Errorf("parseGrantImportID(%q) = (%q, %q), want (%q, %q)", tc.id, gotResource, gotGrantee, tc.wantResource, tc.wantGrantee)
			}
		})
	}
}
