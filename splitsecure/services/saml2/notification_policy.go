package saml2

import notificationsv1 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/notifications/v1"

// HCL surface for notifications.v1.NotificationPolicy. Strings match
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
func notificationPolicyFromString(s string) notificationsv1.NotificationPolicy {
	switch s {
	case notificationPolicySelective:
		return notificationsv1.NotificationPolicy_NOTIFICATION_POLICY_ALLOW_SELECTIVE_NOTIFICATIONS
	default:
		return notificationsv1.NotificationPolicy_NOTIFICATION_POLICY_NOTIFY_EVERYONE
	}
}

// notificationPolicyToString maps the proto enum back to its HCL
// surface form. Unspecified is normalized to NotifyEveryone (server
// behavior) so Read never produces a value the schema rejects.
func notificationPolicyToString(p notificationsv1.NotificationPolicy) string {
	switch p {
	case notificationsv1.NotificationPolicy_NOTIFICATION_POLICY_ALLOW_SELECTIVE_NOTIFICATIONS:
		return notificationPolicySelective
	case notificationsv1.NotificationPolicy_NOTIFICATION_POLICY_NOTIFY_EVERYONE,
		notificationsv1.NotificationPolicy_NOTIFICATION_POLICY_UNSPECIFIED:
		return notificationPolicyNotifyEveryone
	default:
		return notificationPolicyNotifyEveryone
	}
}
