package saml2

import (
	"strings"
	"testing"
)

func TestDestroyJustification(t *testing.T) {
	t.Parallel()

	got := destroyJustification("SAML2 IdP", "engineering/aws-123", "s2r:us:saml2idp:t/r")
	for _, want := range []string{"SAML2 IdP", "engineering/aws-123", "s2r:us:saml2idp:t/r", "terraform destroy"} {
		if !strings.Contains(got, want) {
			t.Fatalf("destroyJustification missing %q in %q", want, got)
		}
	}
}
