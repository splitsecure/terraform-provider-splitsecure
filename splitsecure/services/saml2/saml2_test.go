package saml2_test

import (
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/providerserver"
	"github.com/hashicorp/terraform-plugin-go/tfprotov6"

	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/provider"
)

// testAccProtoV6ProviderFactories is consumed by future TestAcc* cases
// (resource.Test) under TF_ACC=1; collected here so each new acceptance
// test in this package only has to reference the shared map. The
// factory binds the framework provider to protocol v6 because that's
// what `terraform-plugin-framework` speaks.
var testAccProtoV6ProviderFactories = map[string]func() (tfprotov6.ProviderServer, error){
	"splitsecure": providerserver.NewProtocol6WithError(provider.New("test")()),
}

// TestAccProviderFactories_Smoke is a unit-mode (TF_ACC unset) smoke
// test that the provider factory wires up cleanly. Real acceptance
// tests are gated behind TF_ACC=1 + a staging endpoint and live
// alongside the resources they exercise.
func TestAccProviderFactories_Smoke(t *testing.T) {
	t.Parallel()

	factory, ok := testAccProtoV6ProviderFactories["splitsecure"]
	if !ok {
		t.Fatal("splitsecure factory missing from testAccProtoV6ProviderFactories")
	}
	_, err := factory()
	if err != nil {
		t.Fatalf("provider factory returned error: %v", err)
	}
}
