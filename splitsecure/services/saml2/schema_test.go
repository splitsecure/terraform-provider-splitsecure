package saml2

import (
	"context"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
)

func schemaForResource(ctx context.Context, t *testing.T, r resource.Resource) rschema.Schema {
	t.Helper()

	resp := &resource.SchemaResponse{}
	r.Schema(ctx, resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}

	return resp.Schema
}

func TestIDPSchema_RequiredAttributes(t *testing.T) {
	t.Parallel()

	s := schemaForResource(context.Background(), t, NewIdentityProviderResource())

	for _, name := range []string{"vault_id", "name"} {
		attr, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("required attribute %q missing", name)
		}

		if !attr.IsRequired() {
			t.Errorf("attribute %q should be Required", name)
		}
	}
}

func TestIDPSchema_ComputedAttributes(t *testing.T) {
	t.Parallel()

	s := schemaForResource(context.Background(), t, NewIdentityProviderResource())

	for _, name := range []string{
		"id",
		"provider_id",
		"sso_url_redirect",
		"sso_url_post",
		"metadata_xml",
		"signing_certificate_pem",
		"signing_certificate_der",
		"signing_public_key_pem",
		"signing_public_key_der",
		"idp_serial",
	} {
		attr, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("computed attribute %q missing", name)
		}

		if !attr.IsComputed() || attr.IsOptional() || attr.IsRequired() {
			t.Errorf("attribute %q should be Computed only", name)
		}
	}
}

func TestIDPSchema_OptionalInputs(t *testing.T) {
	t.Parallel()

	s := schemaForResource(context.Background(), t, NewIdentityProviderResource())

	for _, name := range []string{"description", "not_before", "not_after", "notification_policy", "sensitivity", "justification", "wait"} {
		attr, ok := s.Attributes[name]
		if !ok {
			t.Fatalf("attribute %q missing", name)
		}

		if !attr.IsOptional() {
			t.Errorf("attribute %q should be Optional", name)
		}
	}
}

func TestIDPSchema_WriteOnlyCreateOptions(t *testing.T) {
	t.Parallel()

	s := schemaForResource(context.Background(), t, NewIdentityProviderResource())

	for _, name := range []string{"justification", "wait"} {
		if !s.Attributes[name].IsWriteOnly() {
			t.Errorf("%q should be WriteOnly so it never lands in state", name)
		}
	}
}

func TestIDPSchema_RemovedProposalAttributes(t *testing.T) {
	t.Parallel()

	s := schemaForResource(context.Background(), t, NewIdentityProviderResource())

	if _, ok := s.Attributes["team_s2r"]; ok {
		t.Error("team_s2r belongs to the proposal flow and should be gone")
	}
}
