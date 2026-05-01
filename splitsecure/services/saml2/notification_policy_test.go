package saml2

import (
	"testing"

	notificationsv1 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/notifications/v1"
)

func TestNotificationPolicyRoundTrip(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name string
		hcl  string
		want notificationsv1.NotificationPolicy
	}{
		{"notify_everyone", notificationPolicyNotifyEveryone, notificationsv1.NotificationPolicy_NOTIFICATION_POLICY_NOTIFY_EVERYONE},
		{"allow_selective", notificationPolicySelective, notificationsv1.NotificationPolicy_NOTIFICATION_POLICY_ALLOW_SELECTIVE_NOTIFICATIONS},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got := notificationPolicyFromString(tc.hcl)
			if got != tc.want {
				t.Fatalf("fromString(%q) = %v, want %v", tc.hcl, got, tc.want)
			}
			back := notificationPolicyToString(got)
			if back != tc.hcl {
				t.Fatalf("round-trip toString(%v) = %q, want %q", got, back, tc.hcl)
			}
		})
	}
}

func TestNotificationPolicyDefaults(t *testing.T) {
	t.Parallel()

	if got := notificationPolicyFromString(""); got != notificationsv1.NotificationPolicy_NOTIFICATION_POLICY_NOTIFY_EVERYONE {
		t.Fatalf("empty fromString = %v, want NOTIFY_EVERYONE", got)
	}
	if got := notificationPolicyFromString("nonsense"); got != notificationsv1.NotificationPolicy_NOTIFICATION_POLICY_NOTIFY_EVERYONE {
		t.Fatalf("unknown fromString = %v, want NOTIFY_EVERYONE", got)
	}
	if got := notificationPolicyToString(notificationsv1.NotificationPolicy_NOTIFICATION_POLICY_UNSPECIFIED); got != notificationPolicyNotifyEveryone {
		t.Fatalf("UNSPECIFIED toString = %q, want %q", got, notificationPolicyNotifyEveryone)
	}
}

// TestNotificationPolicyValuesCoverage asserts every entry in the
// HCL-facing slice has a working forward + backward mapping.
// Catches the classic "added a constant, forgot to wire it into one
// of the converters" mistake.
func TestNotificationPolicyValuesCoverage(t *testing.T) {
	t.Parallel()

	for _, hcl := range notificationPolicyValues() {
		t.Run(hcl, func(t *testing.T) {
			t.Parallel()

			proto := notificationPolicyFromString(hcl)
			if proto == notificationsv1.NotificationPolicy_NOTIFICATION_POLICY_UNSPECIFIED {
				t.Fatalf("%q maps to UNSPECIFIED -- missing branch in notificationPolicyFromString", hcl)
			}
			if back := notificationPolicyToString(proto); back != hcl {
				t.Fatalf("round-trip %q -> %v -> %q", hcl, proto, back)
			}
		})
	}
}
