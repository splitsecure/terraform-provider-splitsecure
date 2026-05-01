package saml2

import (
	"testing"

	teamresourcev1 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/teamresource/v1"
)

func TestSensitivityRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		hcl  string
		want teamresourcev1.AccountSensitivityLevel
	}{
		{"low", sensitivityLow, teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_LOW},
		{"medium", sensitivityMedium, teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_MEDIUM},
		{"high", sensitivityHigh, teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_HIGH},
		{"critical", sensitivityCritical, teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_CRITICAL},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := sensitivityLevelFromString(tc.hcl)
			if got != tc.want {
				t.Fatalf("fromString(%q) = %v, want %v", tc.hcl, got, tc.want)
			}
			back := sensitivityLevelToString(got)
			if back != tc.hcl {
				t.Fatalf("round-trip toString(%v) = %q, want %q", got, back, tc.hcl)
			}

			msg := sensitivityFromString(tc.hcl)
			if msg == nil {
				t.Fatalf("sensitivityFromString(%q) = nil, want a populated AccountSensitivity", tc.hcl)
			}
			if msg.GetLevel() != tc.want {
				t.Fatalf("sensitivityFromString(%q).Level = %v, want %v", tc.hcl, msg.GetLevel(), tc.want)
			}
		})
	}
}

func TestSensitivityUnsetCases(t *testing.T) {
	t.Parallel()

	if got := sensitivityLevelFromString(""); got != teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_UNSPECIFIED {
		t.Fatalf("empty fromString = %v, want UNSPECIFIED", got)
	}
	if got := sensitivityLevelFromString("nonsense"); got != teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_UNSPECIFIED {
		t.Fatalf("unknown fromString = %v, want UNSPECIFIED", got)
	}
	if msg := sensitivityFromString(""); msg != nil {
		t.Fatalf("sensitivityFromString(\"\") = %v, want nil so the wire field stays unset", msg)
	}
	if got := sensitivityLevelToString(teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_UNSPECIFIED); got != "" {
		t.Fatalf("UNSPECIFIED toString = %q, want empty", got)
	}
}

// TestSensitivityValuesCoverage asserts every entry in the HCL-facing
// slice has a working forward + backward mapping. Same intent as the
// notification-policy coverage test.
func TestSensitivityValuesCoverage(t *testing.T) {
	t.Parallel()

	for _, hcl := range sensitivityLevelValues() {
		t.Run(hcl, func(t *testing.T) {
			t.Parallel()

			level := sensitivityLevelFromString(hcl)
			if level == teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_UNSPECIFIED {
				t.Fatalf("%q maps to UNSPECIFIED -- missing branch", hcl)
			}
			if back := sensitivityLevelToString(level); back != hcl {
				t.Fatalf("round-trip %q -> %v -> %q", hcl, level, back)
			}
		})
	}
}
