package org

import (
	"context"
	"errors"
	"slices"
	"strconv"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
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

	removeErr   error
	getGroup    *orgsvcv1.Group
	getGroupErr error
	addResults  []*orgsvcv1.AddGroupMembersResponse_Result
	addErr      error
	listMembers []*orgsvcv1.GroupMember
	listPages   [][]*orgsvcv1.GroupMember // when set, ListGroupMembers serves these pages via cursor
	listErr     error
}

func (f *fakeOrgClient) RemoveGroupMember(
	_ context.Context, _ *connect.Request[orgsvcv1.RemoveGroupMemberRequest],
) (*connect.Response[orgsvcv1.RemoveGroupMemberResponse], error) {
	if f.removeErr != nil {
		return nil, f.removeErr
	}

	return connect.NewResponse(&orgsvcv1.RemoveGroupMemberResponse{}), nil
}

func (f *fakeOrgClient) GetGroup(
	_ context.Context, _ *connect.Request[orgsvcv1.GetGroupRequest],
) (*connect.Response[orgsvcv1.GetGroupResponse], error) {
	if f.getGroupErr != nil {
		return nil, f.getGroupErr
	}

	return connect.NewResponse(&orgsvcv1.GetGroupResponse{Group: f.getGroup}), nil
}

func (f *fakeOrgClient) AddGroupMembers(
	_ context.Context, _ *connect.Request[orgsvcv1.AddGroupMembersRequest],
) (*connect.Response[orgsvcv1.AddGroupMembersResponse], error) {
	if f.addErr != nil {
		return nil, f.addErr
	}

	return connect.NewResponse(&orgsvcv1.AddGroupMembersResponse{Results: f.addResults}), nil
}

func (f *fakeOrgClient) ListGroupMembers(
	_ context.Context, req *connect.Request[orgsvcv1.ListGroupMembersRequest],
) (*connect.Response[orgsvcv1.ListGroupMembersResponse], error) {
	if f.listErr != nil {
		return nil, f.listErr
	}
	if f.listPages != nil { // paginated mode: the cursor is the page index
		i := 0
		if c := req.Msg.GetCursor(); c != "" {
			i, _ = strconv.Atoi(c)
		}
		resp := &orgsvcv1.ListGroupMembersResponse{Members: f.listPages[i]}
		if i+1 < len(f.listPages) {
			resp.NextCursor = strconv.Itoa(i + 1)
		}

		return connect.NewResponse(resp), nil
	}

	return connect.NewResponse(&orgsvcv1.ListGroupMembersResponse{Members: f.listMembers}), nil
}

func TestGroupDataSource_GetByS2R(t *testing.T) {
	t.Parallel()

	d := &groupDataSource{client: &client.Client{
		OrgService: &fakeOrgClient{getGroup: &orgsvcv1.Group{
			GroupS2R: "s2r:test:group:x/y",
			Name:     "SRE",
			Source:   orgsvcv1.GroupSource_GROUP_SOURCE_LOCAL,
		}},
	}}

	var diags diag.Diagnostics
	g := d.getByS2R(context.Background(), "s2r:test:group:x/y", &diags)
	if diags.HasError() {
		t.Fatalf("unexpected diagnostics: %v", diags)
	}
	if g.GetName() != "SRE" || g.GetGroupS2R() != "s2r:test:group:x/y" {
		t.Fatalf("unexpected group: %+v", g)
	}
}

func TestGroupDataSource_GetByS2R_NotFound(t *testing.T) {
	t.Parallel()

	d := &groupDataSource{client: &client.Client{
		OrgService: &fakeOrgClient{getGroupErr: connect.NewError(connect.CodeNotFound, errStub)},
	}}

	var diags diag.Diagnostics
	if g := d.getByS2R(context.Background(), "s2r:test:group:x/y", &diags); g != nil {
		t.Fatalf("expected nil group on NotFound, got %+v", g)
	}
	if !diags.HasError() {
		t.Fatal("expected a diagnostic on NotFound")
	}
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

func TestFetchLocalGroup(t *testing.T) {
	t.Parallel()

	const groupS2R = "s2r:test:group:x/y"
	cases := []struct {
		name       string
		group      *orgsvcv1.Group
		getErr     error
		wantGroup  bool
		wantSource string
		wantErr    bool
	}{
		{
			name:       "local group resolves",
			group:      &orgsvcv1.Group{GroupS2R: groupS2R, Name: "SRE", Source: orgsvcv1.GroupSource_GROUP_SOURCE_LOCAL},
			wantGroup:  true,
			wantSource: "local",
		},
		{
			name:    "scim group is rejected",
			group:   &orgsvcv1.Group{GroupS2R: groupS2R, Source: orgsvcv1.GroupSource_GROUP_SOURCE_SCIM},
			wantErr: true,
		},
		{
			name:    "system group is rejected",
			group:   &orgsvcv1.Group{GroupS2R: groupS2R, Source: orgsvcv1.GroupSource_GROUP_SOURCE_SYSTEM},
			wantErr: true,
		},
		{
			name:    "empty group is rejected",
			group:   &orgsvcv1.Group{},
			wantErr: true,
		},
		{
			// A nil group with no diagnostic is the contract Read relies on
			// to RemoveResource; a surfaced error would abort the read instead.
			name:   "not found returns nil without a diagnostic",
			getErr: connect.NewError(connect.CodeNotFound, errStub),
		},
		{
			name:    "other rpc error is surfaced",
			getErr:  connect.NewError(connect.CodeInternal, errStub),
			wantErr: true,
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &groupResource{client: &client.Client{
				OrgService: &fakeOrgClient{getGroup: tc.group, getGroupErr: tc.getErr},
			}}

			var diags diag.Diagnostics
			g, src := r.fetchLocalGroup(context.Background(), groupS2R, &diags)
			if tc.wantErr {
				if !diags.HasError() {
					t.Fatalf("expected an error diagnostic, got group %+v", g)
				}

				return
			}
			if diags.HasError() {
				t.Fatalf("unexpected diagnostics: %v", diags)
			}
			if tc.wantGroup {
				if g == nil {
					t.Fatal("expected a group")
				}
				if src != tc.wantSource {
					t.Fatalf("source = %q, want %q", src, tc.wantSource)
				}

				return
			}
			if g != nil {
				t.Fatalf("expected nil group, got %+v", g)
			}
		})
	}
}

func TestListMemberPrincipals_RejectsEmptyPrincipal(t *testing.T) {
	t.Parallel()

	r := &groupResource{client: &client.Client{
		OrgService: &fakeOrgClient{listMembers: []*orgsvcv1.GroupMember{
			{PrincipalS2R: "s2r:test:usr:a"},
			{PrincipalS2R: ""},
		}},
	}}

	_, err := r.listMemberPrincipals(context.Background(), "s2r:test:group:x/y")
	if !errors.Is(err, errEmptyMemberPrincipal) {
		t.Fatalf("err = %v, want errEmptyMemberPrincipal", err)
	}
}

func TestListMemberPrincipals_ConsumesAllPages(t *testing.T) {
	t.Parallel()

	r := &groupResource{client: &client.Client{OrgService: &fakeOrgClient{
		listPages: [][]*orgsvcv1.GroupMember{
			{{PrincipalS2R: "s2r:test:usr:a"}, {PrincipalS2R: "s2r:test:usr:b"}},
			{{PrincipalS2R: "s2r:test:usr:c"}},
		},
	}}}

	got, err := r.listMemberPrincipals(context.Background(), "s2r:test:group:x/y")
	if err != nil {
		t.Fatalf("listMemberPrincipals: %v", err)
	}
	want := []string{"s2r:test:usr:a", "s2r:test:usr:b", "s2r:test:usr:c"}
	if !slices.Equal(got, want) {
		t.Fatalf("got %v, want %v (both pages must be consumed)", got, want)
	}
}

func TestReconcileMembers_AddPath(t *testing.T) {
	t.Parallel()

	const groupS2R = "s2r:test:group:x/y"

	t.Run("all additions land", func(t *testing.T) {
		t.Parallel()

		r := &groupResource{client: &client.Client{OrgService: &fakeOrgClient{
			addResults: []*orgsvcv1.AddGroupMembersResponse_Result{
				{PrincipalS2R: "s2r:test:usr:a"},
				{PrincipalS2R: "s2r:test:usr:b"},
			},
		}}}

		current, title, err := r.reconcileMembers(context.Background(), groupS2R, nil, []string{"s2r:test:usr:a", "s2r:test:usr:b"})
		if err != nil {
			t.Fatalf("unexpected error: %v (%s)", err, title)
		}
		slices.Sort(current)
		if !slices.Equal(current, []string{"s2r:test:usr:a", "s2r:test:usr:b"}) {
			t.Fatalf("current = %v, want both principals", current)
		}
	})

	t.Run("partial server rejection returns an error and keeps only landed", func(t *testing.T) {
		t.Parallel()

		r := &groupResource{client: &client.Client{OrgService: &fakeOrgClient{
			addResults: []*orgsvcv1.AddGroupMembersResponse_Result{
				{PrincipalS2R: "s2r:test:usr:a"},
				{PrincipalS2R: "s2r:test:usr:b", Error: "not in org"},
			},
		}}}

		current, title, err := r.reconcileMembers(context.Background(), groupS2R, nil, []string{"s2r:test:usr:a", "s2r:test:usr:b"})
		if !errors.Is(err, errMembersNotAdded) {
			t.Fatalf("err = %v, want errMembersNotAdded", err)
		}
		if title != titleAddingMembers {
			t.Fatalf("title = %q, want %q", title, titleAddingMembers)
		}
		if !slices.Contains(current, "s2r:test:usr:a") {
			t.Fatalf("landed member should be in current: %v", current)
		}
		if slices.Contains(current, "s2r:test:usr:b") {
			t.Fatalf("failed member should not be in current: %v", current)
		}
	})

	t.Run("add rpc error preserves prior members", func(t *testing.T) {
		t.Parallel()

		r := &groupResource{client: &client.Client{OrgService: &fakeOrgClient{
			addErr: connect.NewError(connect.CodeInternal, errStub),
		}}}

		current, title, err := r.reconcileMembers(context.Background(), groupS2R, []string{"s2r:test:usr:x"}, []string{"s2r:test:usr:x", "s2r:test:usr:a"})
		if err == nil {
			t.Fatal("expected the add rpc error to fail the reconcile")
		}
		if title != titleAddingMembers {
			t.Fatalf("title = %q, want %q", title, titleAddingMembers)
		}
		if !slices.Equal(current, []string{"s2r:test:usr:x"}) {
			t.Fatalf("prior members should be preserved on add failure, got %v", current)
		}
	})
}

// TestGroupRead_MemberState covers the null-vs-empty member-set branch
// that keeps imported and member-less groups diff-free.
func TestGroupRead_MemberState(t *testing.T) {
	t.Parallel()

	s := groupResourceSchema(t)
	local := &orgsvcv1.Group{GroupS2R: "s2r:test:group:x/y", Name: "SRE", Source: orgsvcv1.GroupSource_GROUP_SOURCE_LOCAL}

	cases := []struct {
		name         string
		listMembers  []*orgsvcv1.GroupMember
		priorMembers types.Set
		wantNull     bool
		wantMembers  []string
	}{
		{
			name:         "populated membership is refreshed from the server",
			listMembers:  []*orgsvcv1.GroupMember{{PrincipalS2R: "s2r:test:usr:a"}, {PrincipalS2R: "s2r:test:usr:b"}},
			priorMembers: types.SetNull(types.StringType),
			wantMembers:  []string{"s2r:test:usr:a", "s2r:test:usr:b"},
		},
		{
			name:         "empty server membership stays null when prior state was null",
			priorMembers: types.SetNull(types.StringType),
			wantNull:     true,
		},
		{
			name:         "empty server membership becomes an empty set when prior state had members",
			priorMembers: mustMemberSet(t, "s2r:test:usr:a"),
			wantMembers:  []string{},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			r := &groupResource{client: &client.Client{
				OrgService: &fakeOrgClient{getGroup: local, listMembers: tc.listMembers},
			}}
			req := resource.ReadRequest{State: groupStateForRead(t, s, groupResourceModel{
				GroupS2R: types.StringValue(local.GetGroupS2R()),
				Name:     types.StringValue("stale name"),
				Members:  tc.priorMembers,
				Source:   types.StringValue("local"),
			})}
			resp := &resource.ReadResponse{State: tfsdk.State{Schema: s}}

			r.Read(context.Background(), req, resp)
			if resp.Diagnostics.HasError() {
				t.Fatalf("unexpected diagnostics: %v", resp.Diagnostics)
			}

			var got groupResourceModel
			if diags := resp.State.Get(context.Background(), &got); diags.HasError() {
				t.Fatalf("reading result state: %v", diags)
			}
			if got.Name.ValueString() != "SRE" {
				t.Errorf("name = %q, want it refreshed to %q", got.Name.ValueString(), "SRE")
			}
			if tc.wantNull {
				if !got.Members.IsNull() {
					t.Fatalf("members should stay null, got %v", got.Members)
				}

				return
			}
			if got.Members.IsNull() {
				t.Fatal("members should be a non-null set")
			}
			var members []string
			if diags := got.Members.ElementsAs(context.Background(), &members, false); diags.HasError() {
				t.Fatalf("reading members: %v", diags)
			}
			slices.Sort(members)
			if !slices.Equal(members, tc.wantMembers) {
				t.Fatalf("members = %v, want %v", members, tc.wantMembers)
			}
		})
	}
}

func TestGroupRead_RemovesOnNotFound(t *testing.T) {
	t.Parallel()

	s := groupResourceSchema(t)
	model := groupResourceModel{
		GroupS2R: types.StringValue("s2r:test:group:x/y"),
		Name:     types.StringValue("SRE"),
		Members:  types.SetNull(types.StringType),
		Source:   types.StringValue("local"),
	}
	r := &groupResource{client: &client.Client{
		OrgService: &fakeOrgClient{getGroupErr: connect.NewError(connect.CodeNotFound, errStub)},
	}}
	req := resource.ReadRequest{State: groupStateForRead(t, s, model)}
	// Seed the response with the prior state so a missing RemoveResource
	// would leave it non-null and fail the assertion.
	resp := &resource.ReadResponse{State: groupStateForRead(t, s, model)}

	r.Read(context.Background(), req, resp)
	if resp.Diagnostics.HasError() {
		t.Fatalf("NotFound should not surface a diagnostic: %v", resp.Diagnostics)
	}
	if !resp.State.Raw.IsNull() {
		t.Fatal("state should be removed on NotFound")
	}
}

func TestGroupRead_ErrorsWithoutRemovingOnNonLocalSource(t *testing.T) {
	t.Parallel()

	s := groupResourceSchema(t)
	model := groupResourceModel{
		GroupS2R: types.StringValue("s2r:test:group:x/y"),
		Name:     types.StringValue("SRE"),
		Members:  types.SetNull(types.StringType),
		Source:   types.StringValue("local"),
	}
	r := &groupResource{client: &client.Client{
		OrgService: &fakeOrgClient{getGroup: &orgsvcv1.Group{
			GroupS2R: "s2r:test:group:x/y",
			Source:   orgsvcv1.GroupSource_GROUP_SOURCE_SCIM,
		}},
	}}
	req := resource.ReadRequest{State: groupStateForRead(t, s, model)}
	resp := &resource.ReadResponse{State: groupStateForRead(t, s, model)}

	r.Read(context.Background(), req, resp)
	if !resp.Diagnostics.HasError() {
		t.Fatal("a SCIM-sourced group should fail the read")
	}
	if resp.State.Raw.IsNull() {
		t.Fatal("state must not be removed when the read errors")
	}
}

func mustMemberSet(t *testing.T, principals ...string) types.Set {
	t.Helper()

	set, diags := types.SetValueFrom(context.Background(), types.StringType, principals)
	if diags.HasError() {
		t.Fatalf("building member set: %v", diags)
	}

	return set
}

func groupStateForRead(t *testing.T, s rschema.Schema, model groupResourceModel) tfsdk.State {
	t.Helper()

	state := tfsdk.State{Schema: s}
	if diags := state.Set(context.Background(), &model); diags.HasError() {
		t.Fatalf("building state: %v", diags)
	}

	return state
}
