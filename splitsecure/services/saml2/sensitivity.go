package saml2

import teamresourcev1 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/teamresource/v1"

// HCL surface for teamresource.v1.AccountSensitivityLevel. Strings
// match the proto enum suffix in lower_snake_case so the OneOf
// validator drives both schema validation and the description from a
// single source.
const (
	sensitivityLow      = "low"
	sensitivityMedium   = "medium"
	sensitivityHigh     = "high"
	sensitivityCritical = "critical"
)

// sensitivityLevelValues lists the strings users may set on the
// sensitivity attribute. Used for schema-level OneOf validation and
// the schema description.
func sensitivityLevelValues() []string {
	return []string{sensitivityLow, sensitivityMedium, sensitivityHigh, sensitivityCritical}
}

// sensitivityFromString maps an HCL string to a proto AccountSensitivity
// message. Empty / unknown values produce a nil proto so the field
// records as ACCOUNT_SENSITIVITY_LEVEL_UNSPECIFIED on the server.
func sensitivityFromString(s string) *teamresourcev1.AccountSensitivity {
	level := sensitivityLevelFromString(s)
	if level == teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_UNSPECIFIED {
		return nil
	}

	return &teamresourcev1.AccountSensitivity{Level: level}
}

func sensitivityLevelFromString(s string) teamresourcev1.AccountSensitivityLevel {
	switch s {
	case sensitivityLow:
		return teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_LOW
	case sensitivityMedium:
		return teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_MEDIUM
	case sensitivityHigh:
		return teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_HIGH
	case sensitivityCritical:
		return teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_CRITICAL
	default:
		return teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_UNSPECIFIED
	}
}

// sensitivityLevelToString maps the proto enum back to its HCL surface
// form. Unspecified maps to the empty string so Read leaves the
// attribute null when the resource record carries no sensitivity.
func sensitivityLevelToString(l teamresourcev1.AccountSensitivityLevel) string {
	switch l {
	case teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_LOW:
		return sensitivityLow
	case teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_MEDIUM:
		return sensitivityMedium
	case teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_HIGH:
		return sensitivityHigh
	case teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_CRITICAL:
		return sensitivityCritical
	case teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}
