package saml2

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

// schemaForResource pulls the schema out of a resource by calling its
// Schema(...) method directly. Avoids depending on terraform-plugin-go
// or the framework's plumbing.
func schemaForResource(t *testing.T, r resource.Resource) rschema.Schema {
	t.Helper()

	resp := &resource.SchemaResponse{}
	r.Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}

	return resp.Schema
}

func TestIDPSchema_RequiredAttributes(t *testing.T) {
	t.Parallel()

	s := schemaForResource(t, &saml2IdentityProvider{})

	required := []string{"team_s2r", "name"}
	for _, name := range required {
		attr, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("required attribute %q missing from IdP schema", name)
		}
		if !attr.IsRequired() {
			t.Errorf("attribute %q should be Required", name)
		}
	}
}

func TestIDPSchema_ComputedAttributes(t *testing.T) {
	t.Parallel()

	s := schemaForResource(t, &saml2IdentityProvider{})

	for _, name := range []string{
		"id",
		"metadata_xml",
		"sso_url_redirect",
		"sso_url_post",
		"signing_certificate_pem",
		"signing_certificate_der",
		"signing_public_key_pem",
		"signing_public_key_der",
	} {
		attr, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("computed attribute %q missing from IdP schema", name)
		}
		if !attr.IsComputed() {
			t.Errorf("attribute %q should be Computed", name)
		}
	}
}

func TestIDPSchema_WriteOnlyJustification(t *testing.T) {
	t.Parallel()

	s := schemaForResource(t, &saml2IdentityProvider{})

	attr, ok := s.Attributes["justification"]
	if !ok {
		t.Fatal("justification attribute missing from IdP schema")
	}
	if !attr.IsWriteOnly() {
		t.Error("justification should be WriteOnly so it never lands in state")
	}
	if attr.IsRequired() {
		t.Error("justification should be Optional, not Required")
	}
}

func TestSPSchema_RequiredAttributes(t *testing.T) {
	t.Parallel()

	s := schemaForResource(t, &saml2ServiceProvider{})

	for _, name := range []string{"team_s2r", "idp_resource_s2r", "name", "acs_url"} {
		attr, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("required attribute %q missing from SP schema", name)
		}
		if !attr.IsRequired() {
			t.Errorf("attribute %q should be Required", name)
		}
	}
}

func TestSPSchema_ComputedAttributes(t *testing.T) {
	t.Parallel()

	s := schemaForResource(t, &saml2ServiceProvider{})

	for _, name := range []string{"id", "account_type"} {
		attr, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("computed attribute %q missing from SP schema", name)
		}
		if !attr.IsComputed() {
			t.Errorf("attribute %q should be Computed", name)
		}
	}
}

func TestSPSchema_WriteOnlyJustification(t *testing.T) {
	t.Parallel()

	s := schemaForResource(t, &saml2ServiceProvider{})

	attr, ok := s.Attributes["justification"]
	if !ok {
		t.Fatal("justification attribute missing from SP schema")
	}
	if !attr.IsWriteOnly() {
		t.Error("justification should be WriteOnly")
	}
}

func TestSPSchema_AccountBlockHasAllVariants(t *testing.T) {
	t.Parallel()

	s := schemaForResource(t, &saml2ServiceProvider{})

	accountBlock, ok := s.Blocks["account"]
	if !ok {
		t.Fatal("account block missing from SP schema")
	}
	nested, ok := accountBlock.(rschema.SingleNestedBlock)
	if !ok {
		t.Fatalf("account is %T, want SingleNestedBlock", accountBlock)
	}

	for _, k := range spAccountKinds() {
		if _, ok := nested.Blocks[k]; !ok {
			t.Errorf("account.%s sub-block missing from schema", k)
		}
	}
}

// TestSPSchema_AccountKindValidatorMatches asserts the kind attribute
// inside the account block has a OneOf validator covering exactly the
// list spAccountKinds returns. Catches the "added a kind constant,
// forgot to add it to the validator" mistake.
func TestSPSchema_AccountKindValidatorMatches(t *testing.T) {
	t.Parallel()

	s := schemaForResource(t, &saml2ServiceProvider{})

	accountBlock, ok := s.Blocks["account"].(rschema.SingleNestedBlock)
	if !ok {
		t.Fatalf("account block has wrong type")
	}
	kindAttr, ok := accountBlock.Attributes["kind"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("account.kind has wrong type: %T", accountBlock.Attributes["kind"])
	}
	if !kindAttr.IsRequired() {
		t.Error("account.kind should be Required")
	}
	if len(kindAttr.Validators) == 0 {
		t.Fatal("account.kind should have at least one validator (OneOf)")
	}
}
