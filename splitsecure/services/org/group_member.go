package org

import (
	"context"
	"fmt"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	orgsvcv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/orgsvc/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

var (
	_ resource.Resource                = (*groupMemberResource)(nil)
	_ resource.ResourceWithImportState = (*groupMemberResource)(nil)
)

// memberSeparator splits a group s2r from the member s2r in an id. A group s2r has one slash of its own, followed by its group id, never by "s2r:".
const memberSeparator = "/s2r:"

type groupMemberResource struct {
	client *client.Client
}

type groupMemberModel struct {
	ID       types.String `tfsdk:"id"`
	GroupS2R types.String `tfsdk:"group_s2r"`
	Member   types.String `tfsdk:"member"`
}

// NewGroupMember returns a factory for the splitsecure_group_member resource.
func NewGroupMember() resource.Resource {
	return &groupMemberResource{}
}

func (r *groupMemberResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group_member"
}

func (r *groupMemberResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *groupMemberResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	forceNew := []planmodifier.String{stringplanmodifier.RequiresReplace()}

	resp.Schema = schema.Schema{
		Description: "One member of a locally-managed group. Import with group_s2r/member, where both are full s2rs. SCIM and system groups are refused.\n\n" +
			"Choosing a resource: this resource is additive. It adds and removes only its own member and leaves every other member alone. " +
			"Use the members attribute of splitsecure_group instead to own the whole member set. " +
			"Never use both on the same group.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Member id in the form group_s2r/member.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"group_s2r": schema.StringAttribute{
				Required:      true,
				Description:   "Group s2r URI. Changing it replaces the resource.",
				PlanModifiers: forceNew,
				Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"member": schema.StringAttribute{
				Required:      true,
				Description:   "S2r URI of the user or service account to add. Changing it replaces the resource.",
				PlanModifiers: forceNew,
				Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
			},
		},
	}
}

func (r *groupMemberResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan groupMemberModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	group, _ := (&groupResource{client: r.client}).fetchLocalGroup(ctx, plan.GroupS2R.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if group == nil {
		resp.Diagnostics.AddError("Adding group member", "group not found: "+plan.GroupS2R.ValueString())

		return
	}

	added, err := r.client.OrgService.AddGroupMembers(ctx, connect.NewRequest(&orgsvcv1.AddGroupMembersRequest{
		GroupS2R:      plan.GroupS2R.ValueString(),
		PrincipalS2Rs: []string{plan.Member.ValueString()},
	}))
	if err != nil {
		resp.Diagnostics.AddError("Adding group member", err.Error())

		return
	}

	_, failures := partitionAddResults(added.Msg.GetResults())
	if len(failures) > 0 {
		resp.Diagnostics.AddError("Adding group member", strings.Join(failures, "\n"))

		return
	}

	if slices.ContainsFunc(added.Msg.GetResults(), (*orgsvcv1.AddGroupMembersResponse_Result).GetAlreadyMember) {
		importID := memberID(plan.GroupS2R.ValueString(), plan.Member.ValueString())
		resp.Diagnostics.AddError("Group member already exists", "The principal is already a member of the group. Import it with the id "+importID+".")

		return
	}

	plan.ID = types.StringValue(memberID(plan.GroupS2R.ValueString(), plan.Member.ValueString()))

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *groupMemberResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state groupMemberModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	groupRes := &groupResource{client: r.client}

	group, _ := groupRes.fetchLocalGroup(ctx, state.GroupS2R.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	if group == nil {
		resp.State.RemoveResource(ctx)

		return
	}

	members, err := groupRes.listMemberPrincipals(ctx, state.GroupS2R.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Listing group members", err.Error())

		return
	}

	if !slices.Contains(members, state.Member.ValueString()) {
		resp.State.RemoveResource(ctx)

		return
	}

	state.ID = types.StringValue(memberID(state.GroupS2R.ValueString(), state.Member.ValueString()))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is unreachable because every input forces replacement.
func (r *groupMemberResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError("Update not supported", "splitsecure_group_member has no in-place update; every input forces replacement.")
}

func (r *groupMemberResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state groupMemberModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.OrgService.RemoveGroupMember(ctx, connect.NewRequest(&orgsvcv1.RemoveGroupMemberRequest{
		GroupS2R:     state.GroupS2R.ValueString(),
		PrincipalS2R: state.Member.ValueString(),
	}))
	if err != nil && connect.CodeOf(err) != connect.CodeNotFound {
		resp.Diagnostics.AddError("Removing group member", err.Error())
	}
}

func (r *groupMemberResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	groupS2R, member, ok := splitMemberID(req.ID)
	if !ok {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("expected group_s2r/member, got %q", req.ID))

		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("group_s2r"), groupS2R)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("member"), member)...)
}

func memberID(groupS2R, member string) string {
	return groupS2R + "/" + member
}

func splitMemberID(id string) (string, string, bool) {
	i := strings.LastIndex(id, memberSeparator)
	if i <= 0 || !strings.HasPrefix(id, "s2r:") {
		return "", "", false
	}

	return id[:i], id[i+1:], true
}
