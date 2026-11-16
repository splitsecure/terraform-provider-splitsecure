package client

import (
	"testing"

	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/authn"
)

func TestPrincipalOf_ReadsTheKeyOrTheWorkloadAccount(t *testing.T) {
	t.Parallel()

	cases := map[string]struct {
		cfg  Config
		want string
	}{
		"key":      {Config{Key: &authn.Key{ServiceAccountS2R: "s2r:us:sa:key"}}, "s2r:us:sa:key"},
		"workload": {Config{Workload: &authn.Workload{ServiceAccountS2R: "s2r:us:sa:wl"}}, "s2r:us:sa:wl"},
	}

	for name, tc := range cases {
		if got := principalOf(tc.cfg); got != tc.want {
			t.Errorf("%s: principalOf = %q, want %q", name, got, tc.want)
		}
	}
}
