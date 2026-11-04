package org

import (
	"context"
	"strings"
	"testing"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	rschema "github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	orgsvcv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/orgsvc/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

const (
	testGroup  = "s2r:test:group:org1/grp1"
	testMember = "s2r:test:user:u1"
)

func memberSchema(t *testing.T) rschema.Schema {
	t.Helper()

	resp := &resource.SchemaResponse{}
	NewGroupMember().Schema(context.Background(), resource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}

	return resp.Schema
}

func memberState(t *testing.T, m *groupMemberModel) tfsdk.State {
	t.Helper()

	s := memberSchema(t)
	state := tfsdk.State{Schema: s, Raw: tftypes.NewValue(s.Type().TerraformType(context.Background()), nil)}

	if diags := state.Set(context.Background(), m); diags.HasError() {
		t.Fatalf("building state: %v", diags)
	}

	return state
}

func memberModel() *groupMemberModel {
	return &groupMemberModel{ID: types.StringUnknown(), GroupS2R: types.StringValue(testGroup), Member: types.StringValue(testMember)}
}

func localGroup() *orgsvcv1.Group {
	return &orgsvcv1.Group{GroupS2R: testGroup, Name: "SRE", Source: orgsvcv1.GroupSource_GROUP_SOURCE_LOCAL}
}

func memberResource(org *memberCalls) *groupMemberResource {
	return &groupMemberResource{client: &client.Client{OrgService: org}}
}

func TestGroupMemberCreate_AddsExactlyOneMember(t *testing.T) {
	t.Parallel()

	org := &memberCalls{fakeOrgClient: fakeOrgClient{getGroup: localGroup()}}
	plan := memberState(t, memberModel())
	resp := &resource.CreateResponse{State: memberState(t, memberModel())}

	memberResource(org).Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan{Schema: plan.Schema, Raw: plan.Raw}}, resp)

	if resp.Diagnostics.HasError() || org.adds != 1 || org.addReq.GetGroupS2R() != testGroup || len(org.addReq.GetPrincipalS2Rs()) != 1 || org.addReq.GetPrincipalS2Rs()[0] != testMember {
		t.Fatalf("adds = %d, request = %v, diags = %v", org.adds, org.addReq, resp.Diagnostics)
	}

	var got groupMemberModel

	resp.State.Get(context.Background(), &got)

	if got.ID.ValueString() != testGroup+"/"+testMember {
		t.Errorf("id = %q", got.ID.ValueString())
	}
}

func TestGroupMemberCreate_RefusesScimAndSystemGroups(t *testing.T) {
	t.Parallel()

	for name, source := range map[string]orgsvcv1.GroupSource{"scim": orgsvcv1.GroupSource_GROUP_SOURCE_SCIM, "system": orgsvcv1.GroupSource_GROUP_SOURCE_SYSTEM} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			org := &memberCalls{fakeOrgClient: fakeOrgClient{getGroup: &orgsvcv1.Group{GroupS2R: testGroup, Source: source}}}
			plan := memberState(t, memberModel())
			resp := &resource.CreateResponse{State: memberState(t, memberModel())}

			memberResource(org).Create(context.Background(), resource.CreateRequest{Plan: tfsdk.Plan{Schema: plan.Schema, Raw: plan.Raw}}, resp)

			if !resp.Diagnostics.HasError() || org.adds != 0 || !strings.Contains(resp.Diagnostics.Errors()[0].Summary(), "not locally managed") {
				t.Errorf("adds = %d, diags = %v", org.adds, resp.Diagnostics)
			}
		})
	}
}

func TestGroupMemberRead_ClearsStateWhenMemberOrGroupIsGone(t *testing.T) {
	t.Parallel()

	cases := map[string]*memberCalls{
		"member absent": {fakeOrgClient: fakeOrgClient{getGroup: localGroup()}, members: []*orgsvcv1.GroupMember{{PrincipalS2R: "s2r:test:user:other"}}},
		"group gone":    {fakeOrgClient: fakeOrgClient{getGroupErr: connect.NewError(connect.CodeNotFound, errStub)}},
	}

	for name, org := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			state := memberState(t, memberModel())
			resp := &resource.ReadResponse{State: state}

			memberResource(org).Read(context.Background(), resource.ReadRequest{State: state}, resp)

			if resp.Diagnostics.HasError() || !resp.State.Raw.IsNull() {
				t.Errorf("state should be removed; diags = %v", resp.Diagnostics)
			}
		})
	}
}

func TestGroupMemberRead_KeepsStateWhenMemberIsPresent(t *testing.T) {
	t.Parallel()

	org := &memberCalls{fakeOrgClient: fakeOrgClient{getGroup: localGroup()}, members: []*orgsvcv1.GroupMember{{PrincipalS2R: "s2r:test:user:other"}, {PrincipalS2R: testMember}}}
	state := memberState(t, memberModel())
	resp := &resource.ReadResponse{State: state}

	memberResource(org).Read(context.Background(), resource.ReadRequest{State: state}, resp)

	if resp.Diagnostics.HasError() || resp.State.Raw.IsNull() {
		t.Errorf("state should stay; diags = %v", resp.Diagnostics)
	}
}

func TestGroupMemberDelete_RemovesOnlyThatMember(t *testing.T) {
	t.Parallel()

	org := &memberCalls{}
	resp := &resource.DeleteResponse{}

	memberResource(org).Delete(context.Background(), resource.DeleteRequest{State: memberState(t, memberModel())}, resp)

	if resp.Diagnostics.HasError() || org.removes != 1 || org.removeReq.GetGroupS2R() != testGroup || org.removeReq.GetPrincipalS2R() != testMember {
		t.Errorf("removes = %d, request = %v, diags = %v", org.removes, org.removeReq, resp.Diagnostics)
	}
}

func TestGroupMemberImport_SplitsGroupAndMember(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	empty := memberState(t, memberModel())
	empty.Raw = tftypes.NewValue(empty.Schema.Type().TerraformType(ctx), nil)

	resp := &resource.ImportStateResponse{State: empty}
	(&groupMemberResource{}).ImportState(ctx, resource.ImportStateRequest{ID: testGroup + "/" + testMember}, resp)

	var got groupMemberModel

	resp.State.Get(ctx, &got)

	if resp.Diagnostics.HasError() || got.GroupS2R.ValueString() != testGroup || got.Member.ValueString() != testMember {
		t.Errorf("state = %+v, diags = %v", got, resp.Diagnostics)
	}

	for _, bad := range []string{"", testGroup, testMember, "nope/s2r:x"} {
		r := &resource.ImportStateResponse{State: empty}
		(&groupMemberResource{}).ImportState(ctx, resource.ImportStateRequest{ID: bad}, r)

		if !r.Diagnostics.HasError() {
			t.Errorf("import id %q should be rejected", bad)
		}
	}
}
