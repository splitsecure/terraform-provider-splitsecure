package org

import (
	"context"
	"errors"
	"slices"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	orgsvcv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/orgsvc/v1"
	"github.com/splitsecure/apis/gen/go/proto/splitsecure/orgsvc/v1/orgsvcv1connect"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

var errStub = errors.New("stub rpc error")

// fakeOrgClient embeds the OrgService client so only the methods a test
// exercises need overriding; any other call panics on the nil embed.
type fakeOrgClient struct {
	orgsvcv1connect.OrgServiceClient

	removeErr error
}

func (f *fakeOrgClient) RemoveGroupMember(
	_ context.Context, _ *connect.Request[orgsvcv1.RemoveGroupMemberRequest],
) (*connect.Response[orgsvcv1.RemoveGroupMemberResponse], error) {
	if f.removeErr != nil {
		return nil, f.removeErr
	}

	return connect.NewResponse(&orgsvcv1.RemoveGroupMemberResponse{}), nil
}

func reconcileWithRemoveErr(t *testing.T, removeErr error) ([]string, string, error) {
	t.Helper()

	r := &groupResource{client: &client.Client{
		OrgService: &fakeOrgClient{removeErr: removeErr},
		OrgS2R:     "s2r:test:org:x",
	}}

	// State lists one principal, plan lists none -> the member is removed.
	return r.reconcileMembers(context.Background(), "s2r:test:group:x/y", []string{"s2r:test:usr:a"}, nil)
}

func TestReconcileMembers_RemoveToleratesNotFound(t *testing.T) {
	t.Parallel()

	current, title, err := reconcileWithRemoveErr(t, connect.NewError(connect.CodeNotFound, errStub))
	if err != nil {
		t.Fatalf("NotFound removal should be tolerated, got error %v (%s)", err, title)
	}
	if len(current) != 0 {
		t.Fatalf("principal should be dropped from current, got %v", current)
	}
}

func TestReconcileMembers_RemoveOtherErrorFails(t *testing.T) {
	t.Parallel()

	current, title, err := reconcileWithRemoveErr(t, connect.NewError(connect.CodeInternal, errStub))
	if err == nil {
		t.Fatal("non-NotFound removal error should fail the reconcile")
	}
	if title != "Removing group member" {
		t.Fatalf("unexpected error title %q", title)
	}
	if !slices.Equal(current, []string{"s2r:test:usr:a"}) {
		t.Fatalf("failed removal should leave the principal in current, got %v", current)
	}
}

func groupResourceSchema(t *testing.T) rschema.Schema {
	t.Helper()

	resp := &resource.SchemaResponse{}
	(&groupResource{}).Schema(context.Background(), resource.SchemaRequest{}, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}

	return resp.Schema
}

func TestGroupSchema_AttributeModes(t *testing.T) {
	t.Parallel()

	s := groupResourceSchema(t)

	name, ok := s.Attributes["name"]
	if !ok {
		t.Fatal("name attribute missing from group schema")
	}
	if !name.IsRequired() {
		t.Error("name should be Required")
	}

	members, ok := s.Attributes["members"]
	if !ok {
		t.Fatal("members attribute missing from group schema")
	}
	if !members.IsOptional() || members.IsRequired() || members.IsComputed() {
		t.Error("members should be Optional only (authoritative config-owned set)")
	}

	for _, attrName := range []string{"group_s2r", "source"} {
		attr, ok := s.Attributes[attrName]
		if !ok {
			t.Fatalf("computed attribute %q missing from group schema", attrName)
		}
		if !attr.IsComputed() {
			t.Errorf("attribute %q should be Computed", attrName)
		}
	}
}

func TestGroupSchema_MembersIsStringSet(t *testing.T) {
	t.Parallel()

	s := groupResourceSchema(t)

	members, ok := s.Attributes["members"].(rschema.SetAttribute)
	if !ok {
		t.Fatalf("members is %T, want SetAttribute", s.Attributes["members"])
	}
	if !members.ElementType.Equal(types.StringType) {
		t.Errorf("members element type is %s, want string", members.ElementType)
	}
}

// TestGroupSchema_GroupS2RKeepsState catches removal of the
// UseStateForUnknown modifier, which would flip group_s2r to "known
// after apply" on every update.
func TestGroupSchema_GroupS2RKeepsState(t *testing.T) {
	t.Parallel()

	s := groupResourceSchema(t)

	attr, ok := s.Attributes["group_s2r"].(rschema.StringAttribute)
	if !ok {
		t.Fatalf("group_s2r is %T, want StringAttribute", s.Attributes["group_s2r"])
	}
	if len(attr.PlanModifiers) == 0 {
		t.Error("group_s2r should carry the UseStateForUnknown plan modifier")
	}
}

func TestGroupSourceMapping(t *testing.T) {
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
		{name: "unknown enum value returns error", source: orgsvcv1.GroupSource(42), wantError: true},
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
				t.Fatalf("groupSourceToString(%v) = %q, want %q", tc.source, got, tc.want)
			}
		})
	}
}

func TestDiffMembers(t *testing.T) {
	t.Parallel()

	cases := []struct {
		name       string
		state      []string
		plan       []string
		wantAdd    []string
		wantRemove []string
	}{
		{
			name:  "no change",
			state: []string{"s2r:us:user:a", "s2r:us:user:b"},
			plan:  []string{"s2r:us:user:b", "s2r:us:user:a"},
		},
		{
			name:    "pure additions",
			state:   []string{"s2r:us:user:a"},
			plan:    []string{"s2r:us:user:a", "s2r:us:user:c", "s2r:us:user:b"},
			wantAdd: []string{"s2r:us:user:b", "s2r:us:user:c"},
		},
		{
			name:       "pure removals",
			state:      []string{"s2r:us:user:a", "s2r:us:user:b"},
			plan:       []string{"s2r:us:user:a"},
			wantRemove: []string{"s2r:us:user:b"},
		},
		{
			name:       "mixed add and remove",
			state:      []string{"s2r:us:user:a", "s2r:us:user:b"},
			plan:       []string{"s2r:us:user:b", "s2r:us:sa:x"},
			wantAdd:    []string{"s2r:us:sa:x"},
			wantRemove: []string{"s2r:us:user:a"},
		},
		{
			name:    "from empty",
			plan:    []string{"s2r:us:user:a"},
			wantAdd: []string{"s2r:us:user:a"},
		},
		{
			name:       "to empty",
			state:      []string{"s2r:us:user:a"},
			wantRemove: []string{"s2r:us:user:a"},
		},
		{
			name: "both empty",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			gotAdd, gotRemove := diffMembers(tc.state, tc.plan)
			if !slices.Equal(gotAdd, tc.wantAdd) {
				t.Errorf("toAdd = %v, want %v", gotAdd, tc.wantAdd)
			}
			if !slices.Equal(gotRemove, tc.wantRemove) {
				t.Errorf("toRemove = %v, want %v", gotRemove, tc.wantRemove)
			}
		})
	}
}

func TestPartitionAddResults(t *testing.T) {
	t.Parallel()

	results := []*orgsvcv1.AddGroupMembersResponse_Result{
		{PrincipalS2R: "s2r:us:user:ok"},
		{PrincipalS2R: "s2r:us:user:dupe", AlreadyMember: true},
		{PrincipalS2R: "s2r:us:user:bad", Error: "principal not found"},
		{PrincipalS2R: "s2r:us:sa:worse", Error: "not in org"},
	}

	added, failures := partitionAddResults(results)

	wantAdded := []string{"s2r:us:user:ok", "s2r:us:user:dupe"}
	if !slices.Equal(added, wantAdded) {
		t.Errorf("added = %v, want %v", added, wantAdded)
	}

	if len(failures) != 2 {
		t.Fatalf("got %d failures, want 2: %v", len(failures), failures)
	}
	for i, want := range []struct{ principal, reason string }{
		{"s2r:us:user:bad", "principal not found"},
		{"s2r:us:sa:worse", "not in org"},
	} {
		if !strings.Contains(failures[i], want.principal) || !strings.Contains(failures[i], want.reason) {
			t.Errorf("failures[%d] = %q, want it to mention %q and %q", i, failures[i], want.principal, want.reason)
		}
	}
}

func TestPartitionAddResults_AllSucceed(t *testing.T) {
	t.Parallel()

	added, failures := partitionAddResults([]*orgsvcv1.AddGroupMembersResponse_Result{
		{PrincipalS2R: "s2r:us:user:a"},
		{PrincipalS2R: "s2r:us:user:b", AlreadyMember: true},
	})

	if !slices.Equal(added, []string{"s2r:us:user:a", "s2r:us:user:b"}) {
		t.Errorf("added = %v, want both principals", added)
	}
	if len(failures) != 0 {
		t.Errorf("failures = %v, want none", failures)
	}
}

func TestPartitionAddResults_EmptyInputYieldsNonNilAdded(t *testing.T) {
	t.Parallel()

	added, failures := partitionAddResults(nil)

	// A non-nil slice matters: types.SetValueFrom turns nil into a
	// null set, which would corrupt the partial-failure state write.
	if added == nil {
		t.Error("added should be non-nil for empty input")
	}
	if len(added) != 0 || len(failures) != 0 {
		t.Errorf("added = %v, failures = %v, want both empty", added, failures)
	}
}
