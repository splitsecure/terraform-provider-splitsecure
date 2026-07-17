package org

import (
	"strings"
	"testing"

	orgsvcv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/orgsvc/v1"
)

func TestSingleMember(t *testing.T) {
	t.Parallel()

	// The server resolves emails to members (canonicalization, ambiguity); the
	// client only extracts the single member from the per-email Result. Matching
	// is by the request email string the server echoes back.
	oneResult := func(email string, members ...*orgsvcv1.Member) []*orgsvcv1.GetMembersByEmailResponse_Result {
		return []*orgsvcv1.GetMembersByEmailResponse_Result{{Email: email, Members: members}}
	}
	alice := &orgsvcv1.Member{UserId: "s2r:us:usr:alice", Email: "alice@example.com", DisplayName: "Alice"}
	carol1 := &orgsvcv1.Member{UserId: "s2r:us:usr:carol1", Email: "carol@example.com", DisplayName: "Carol One"}
	carol2 := &orgsvcv1.Member{UserId: "s2r:us:usr:carol2", Email: "carol@example.com", DisplayName: "Carol Two"}

	cases := []struct {
		name        string
		email       string
		results     []*orgsvcv1.GetMembersByEmailResponse_Result
		wantUserID  string
		wantErrPart string // empty means the lookup must succeed
	}{
		{name: "single member resolves", email: "alice@example.com", results: oneResult("alice@example.com", alice), wantUserID: "s2r:us:usr:alice"},
		{name: "ambiguous email returns error listing matches", email: "carol@example.com", results: oneResult("carol@example.com", carol1, carol2), wantErrPart: "s2r:us:usr:carol2"},
		{name: "empty members returns error naming the email", email: "dave@example.com", results: oneResult("dave@example.com"), wantErrPart: "dave@example.com"},
		{name: "no matching result returns error naming the email", email: "erin@example.com", results: oneResult("alice@example.com", alice), wantErrPart: "erin@example.com"},
		{name: "empty results returns error", email: "alice@example.com", results: nil, wantErrPart: "alice@example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := singleMember(tc.results, tc.email)
			if tc.wantErrPart != "" {
				if err == nil {
					t.Fatalf("singleMember(%q) = %+v, want error", tc.email, got)
				}
				if !strings.Contains(err.Error(), tc.wantErrPart) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErrPart)
				}

				return
			}
			if err != nil {
				t.Fatalf("singleMember(%q): %v", tc.email, err)
			}
			if got.GetUserId() != tc.wantUserID {
				t.Fatalf("got user %q, want %q", got.GetUserId(), tc.wantUserID)
			}
		})
	}
}

func TestGroupSourceToString(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name      string
		source    orgsvcv1.GroupSource
		want      string
		wantError bool
	}{
		{name: "local", source: orgsvcv1.GroupSource_GROUP_SOURCE_LOCAL, want: "local"},
		{name: "scim", source: orgsvcv1.GroupSource_GROUP_SOURCE_SCIM, want: "scim"},
		{name: "system", source: orgsvcv1.GroupSource_GROUP_SOURCE_SYSTEM, want: "system"},
		{name: "unspecified returns error", source: orgsvcv1.GroupSource_GROUP_SOURCE_UNSPECIFIED, wantError: true},
		{name: "out-of-range value returns error", source: orgsvcv1.GroupSource(99), wantError: true},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			got, err := groupSourceToString(tc.source)
			if tc.wantError {
				if err == nil {
					t.Fatalf("groupSourceToString(%v) = %q, want error", tc.source, got)
				}

				return
			}
			if err != nil {
				t.Fatalf("groupSourceToString(%v): %v", tc.source, err)
			}
			if got != tc.want {
				t.Fatalf("got %q, want %q", got, tc.want)
			}
		})
	}
}
