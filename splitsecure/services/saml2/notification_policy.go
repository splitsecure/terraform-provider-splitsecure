package saml2

import teamresourcev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/teamresource/v1"

// HCL surface for teamresource.v1.NotificationPolicy. Strings match
// the proto enum suffix in lower_snake_case so HCL stays readable
// while the Validators.OneOf set still gives a single source of truth.
const (
	notificationPolicyNotifyEveryone = "notify_everyone"
	notificationPolicySelective      = "allow_selective_notifications"
)

// notificationPolicyValues lists the strings users may set on the
// notification_policy attribute. Used for both schema-level OneOf
// validation and the schema description.
func notificationPolicyValues() []string {
	return []string{notificationPolicyNotifyEveryone, notificationPolicySelective}
}

// notificationPolicyFromString maps an HCL string to the proto enum.
// Empty / unknown values default to NotifyEveryone, matching the
// server-side default and the web frontend's create payload.
func notificationPolicyFromString(s string) teamresourcev1.NotificationPolicy {
	switch s {
	case notificationPolicySelective:
		return teamresourcev1.NotificationPolicy_NOTIFICATION_POLICY_ALLOW_SELECTIVE_NOTIFICATIONS
	default:
		return teamresourcev1.NotificationPolicy_NOTIFICATION_POLICY_NOTIFY_EVERYONE
	}
}

// notificationPolicyToString maps the proto enum back to its HCL
// surface form. Unspecified is normalized to NotifyEveryone (server
// behavior) so Read never produces a value the schema rejects.
func notificationPolicyToString(p teamresourcev1.NotificationPolicy) string {
	switch p {
	case teamresourcev1.NotificationPolicy_NOTIFICATION_POLICY_ALLOW_SELECTIVE_NOTIFICATIONS:
		return notificationPolicySelective
	case teamresourcev1.NotificationPolicy_NOTIFICATION_POLICY_NOTIFY_EVERYONE,
		teamresourcev1.NotificationPolicy_NOTIFICATION_POLICY_UNSPECIFIED:
		return notificationPolicyNotifyEveryone
	default:
		return notificationPolicyNotifyEveryone
	}
}
