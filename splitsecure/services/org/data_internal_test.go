package org

import (
	"strings"
	"testing"

	orgsvcv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/orgsvc/v1"
)

func TestMatchMemberByEmail(t *testing.T) {
	t.Parallel()

	members := []*orgsvcv1.Member{
		{UserId: "s2r:us:usr:alice", Email: "alice@example.com", DisplayName: "Alice"},
		{UserId: "s2r:us:usr:bob", Email: "Bob@Example.COM", DisplayName: "Bob"},
		{UserId: "s2r:us:usr:carol1", Email: "carol@example.com", DisplayName: "Carol One"},
		{UserId: "s2r:us:usr:carol2", Email: "CAROL@example.com", DisplayName: "Carol Two"},
	}

	cases := []struct {
		name        string
		email       string
		wantUserID  string
		wantErrPart string // empty means the lookup must succeed
	}{
		{name: "exact match", email: "alice@example.com", wantUserID: "s2r:us:usr:alice"},
		{name: "case-insensitive match", email: "bob@example.com", wantUserID: "s2r:us:usr:bob"},
		{name: "mixed-case query matches stored lowercase", email: "ALICE@EXAMPLE.COM", wantUserID: "s2r:us:usr:alice"},
		{name: "ambiguous email returns error listing matches", email: "carol@example.com", wantErrPart: "s2r:us:usr:carol2"},
		{name: "absent email returns error naming the email", email: "dave@example.com", wantErrPart: "dave@example.com"},
		{name: "empty member list returns error", email: "alice@example.com", wantErrPart: "alice@example.com"},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			in := members
			if tc.name == "empty member list returns error" {
				in = nil
			}

			got, err := matchMemberByEmail(in, tc.email)
			if tc.wantErrPart != "" {
				if err == nil {
					t.Fatalf("matchMemberByEmail(%q) = %+v, want error", tc.email, got)
				}
				if !strings.Contains(err.Error(), tc.wantErrPart) {
					t.Fatalf("error %q does not contain %q", err.Error(), tc.wantErrPart)
				}

				return
			}
			if err != nil {
				t.Fatalf("matchMemberByEmail(%q): %v", tc.email, err)
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
