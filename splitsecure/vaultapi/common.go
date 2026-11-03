package vaultapi

import (
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/durationpb"

	teamresourcev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/teamresource/v1"
	vaultusev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1"
)

// HCL surface of teamresourcev1.NotificationPolicy.
const (
	NotificationPolicyNotifyEveryone = "notify_everyone"
	NotificationPolicySelective      = "allow_selective_notifications"
)

// HCL surface of teamresourcev1.AccountSensitivityLevel.
const (
	SensitivityLow      = "low"
	SensitivityMedium   = "medium"
	SensitivityHigh     = "high"
	SensitivityCritical = "critical"
)

// NotificationPolicyValues lists the accepted notification_policy strings.
func NotificationPolicyValues() []string {
	return []string{NotificationPolicyNotifyEveryone, NotificationPolicySelective}
}

// SensitivityValues lists the accepted sensitivity strings.
func SensitivityValues() []string {
	return []string{SensitivityLow, SensitivityMedium, SensitivityHigh, SensitivityCritical}
}

// NotificationPolicyFromString maps an HCL string to the proto enum, defaulting to notify everyone.
func NotificationPolicyFromString(s string) teamresourcev1.NotificationPolicy {
	if s == NotificationPolicySelective {
		return teamresourcev1.NotificationPolicy_NOTIFICATION_POLICY_ALLOW_SELECTIVE_NOTIFICATIONS
	}

	return teamresourcev1.NotificationPolicy_NOTIFICATION_POLICY_NOTIFY_EVERYONE
}

// NotificationPolicyToString maps the proto enum to its HCL string, defaulting to notify everyone.
func NotificationPolicyToString(p teamresourcev1.NotificationPolicy) string {
	if p == teamresourcev1.NotificationPolicy_NOTIFICATION_POLICY_ALLOW_SELECTIVE_NOTIFICATIONS {
		return NotificationPolicySelective
	}

	return NotificationPolicyNotifyEveryone
}

// SensitivityFromString maps an HCL string to a proto message, or nil when the string is empty or unknown.
func SensitivityFromString(s string) *teamresourcev1.AccountSensitivity {
	levels := map[string]teamresourcev1.AccountSensitivityLevel{
		SensitivityLow:      teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_LOW,
		SensitivityMedium:   teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_MEDIUM,
		SensitivityHigh:     teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_HIGH,
		SensitivityCritical: teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_CRITICAL,
	}

	level, ok := levels[s]
	if !ok {
		return nil
	}

	return &teamresourcev1.AccountSensitivity{Level: level}
}

// SensitivityToString maps the proto message to its HCL string, or "" when unset.
func SensitivityToString(s *teamresourcev1.AccountSensitivity) string {
	switch s.GetLevel() {
	case teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_LOW:
		return SensitivityLow
	case teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_MEDIUM:
		return SensitivityMedium
	case teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_HIGH:
		return SensitivityHigh
	case teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_CRITICAL:
		return SensitivityCritical
	case teamresourcev1.AccountSensitivityLevel_ACCOUNT_SENSITIVITY_LEVEL_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}

// CreateCommonInput carries the HCL values every vault create shares.
type CreateCommonInput struct {
	Name               string
	Description        string
	NotificationPolicy string
	Sensitivity        string
	ParentNodeID       string
}

// CreateCommon builds the shared create fields.
func CreateCommon(in CreateCommonInput) *vaultusev1.CreateCommon {
	return &vaultusev1.CreateCommon{
		Name:                  in.Name,
		Description:           in.Description,
		NotificationPolicy:    NotificationPolicyFromString(in.NotificationPolicy),
		Sensitivity:           SensitivityFromString(in.Sensitivity),
		RequestedParentNodeId: in.ParentNodeID,
	}
}

// WriteOptions builds the write options from a justification and a Go duration string, either of which may be empty.
func WriteOptions(justification, wait string) (*vaultusev1.WriteOptions, error) {
	opts := &vaultusev1.WriteOptions{Justification: justification}

	if wait != "" {
		d, err := time.ParseDuration(wait)
		if err != nil {
			return nil, fmt.Errorf("parsing wait: %w", err)
		}

		opts.Wait = durationpb.New(d)
	}

	return opts, nil
}
