package org

import "testing"

func TestPrincipalKindFromS2R(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		s2r       string
		want      string
		wantError bool
	}{
		{name: "user", s2r: "s2r:local-aliaksei:usr:abc123", want: "user"},
		{name: "service account", s2r: "s2r:local-aliaksei:sa:abc123", want: "service_account"},
		{name: "unexpected kind", s2r: "s2r:us:group:abc123", wantError: true},
		{name: "too few segments", s2r: "s2r:us:usr", wantError: true},
		{name: "not an s2r", s2r: "usr:abc123", wantError: true},
		{name: "empty", s2r: "", wantError: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := principalKindFromS2R(tc.s2r)
			if tc.wantError {
				if err == nil {
					t.Fatalf("principalKindFromS2R(%q) = %q, want error", tc.s2r, got)
				}

				return
			}
			if err != nil {
				t.Fatalf("principalKindFromS2R(%q): %v", tc.s2r, err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
