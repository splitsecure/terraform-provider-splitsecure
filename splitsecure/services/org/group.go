package org

import (
	"context"
	"errors"
	"fmt"
	"sort"
	"strings"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
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
	_ resource.Resource                = (*groupResource)(nil)
	_ resource.ResourceWithImportState = (*groupResource)(nil)
)

const (
	titleCreatingGroup = "Creating group"
	titleAddingMembers = "Adding group members"
	titleReadingGroup  = "Reading group"
)

var (
	errEmptyGroup           = errors.New("CreateGroup returned no group_s2r; the group may exist server-side but cannot be tracked in state")
	errMembersNotAdded      = errors.New("some members could not be added")
	errEmptyMemberPrincipal = errors.New("ListGroupMembers returned a member with an empty principal_s2r")
)

type groupResource struct {
	client *client.Client
}

type groupResourceModel struct {
	GroupS2R types.String `tfsdk:"group_s2r"`
	Name     types.String `tfsdk:"name"`
	Members  types.Set    `tfsdk:"members"`
	Source   types.String `tfsdk:"source"`
}

// NewGroup returns a factory for the org group resource.
func NewGroup() resource.Resource {
	return &groupResource{}
}

func (r *groupResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (r *groupResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *groupResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Locally-managed principal group in the provider-configured organization. " +
			"Terraform is authoritative over the member set; SCIM- and system-managed groups cannot be managed by this resource.",
		Attributes: map[string]schema.Attribute{
			"group_s2r": schema.StringAttribute{
				Computed:      true,
				Description:   "Group s2r URI. Stable identifier; also the import ID.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Human-readable group name. Changing it updates the group in place.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"members": schema.SetAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Authoritative set of member principal s2r URIs (users or service accounts). " +
					"Principals not listed here are removed on apply. Leave unset for an empty group.",
			},
			"source": schema.StringAttribute{
				Computed:      true,
				Description:   `Where the group is managed from: "local", "scim", or "system". Always "local" for Terraform-managed groups.`,
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
		},
	}
}

func (r *groupResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan groupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	configured := membersFromSet(ctx, plan.Members, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	groupS2R, src, err := r.createGroupShell(ctx, plan.Name.ValueString())
	if err != nil {
		if groupS2R != "" {
			// The group exists; record it so it is not orphaned from state.
			plan.GroupS2R = types.StringValue(groupS2R)
			plan.Source = types.StringNull()
			if len(configured) > 0 {
				plan.Members = types.SetNull(types.StringType)
			}
			resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		}
		resp.Diagnostics.AddError(titleCreatingGroup, err.Error())

		return
	}
	plan.GroupS2R = types.StringValue(groupS2R)
	plan.Source = types.StringValue(src)

	if len(configured) == 0 {
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)

		return
	}

	addResp, err := r.client.OrgService.AddGroupMembers(ctx, connect.NewRequest(&orgsvcv1.AddGroupMembersRequest{
		GroupS2R:      groupS2R,
		PrincipalS2Rs: configured,
	}))
	if err != nil {
		// Membership is unknown after a wholesale RPC failure; record
		// the group itself so it is not orphaned from state.
		plan.Members = types.SetNull(types.StringType)
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		resp.Diagnostics.AddError(titleAddingMembers, err.Error())

		return
	}

	landed, failures := partitionAddResults(addResp.Msg.GetResults())
	if len(failures) > 0 {
		landedSet, d := types.SetValueFrom(ctx, types.StringType, landed)
		resp.Diagnostics.Append(d...)
		plan.Members = landedSet
		resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
		resp.Diagnostics.AddError(
			titleAddingMembers,
			fmt.Sprintf("group %s was created and recorded in state, but some members could not be added:\n%s",
				groupS2R, strings.Join(failures, "\n")),
		)

		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *groupResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state groupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	g, src := r.fetchLocalGroup(ctx, state.GroupS2R.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}
	if g == nil {
		resp.State.RemoveResource(ctx)

		return
	}

	principals, err := r.listMemberPrincipals(ctx, g.GetGroupS2R())
	if err != nil {
		resp.Diagnostics.AddError("Listing group members", err.Error())

		return
	}

	state.Name = types.StringValue(g.GetName())
	state.Source = types.StringValue(src)
	// An unset members attribute means empty membership; keep it null
	// when the group is in fact empty so imports and member-less
	// configs stay diff-free.
	if len(principals) > 0 || !state.Members.IsNull() {
		membersVal, d := types.SetValueFrom(ctx, types.StringType, principals)
		resp.Diagnostics.Append(d...)
		if resp.Diagnostics.HasError() {
			return
		}
		state.Members = membersVal
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *groupResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state groupResourceModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	groupS2R := state.GroupS2R.ValueString()
	planMembers := membersFromSet(ctx, plan.Members, &resp.Diagnostics)
	stateMembers := membersFromSet(ctx, state.Members, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	// applied tracks what has actually been persisted server-side so
	// far; error paths write it to state because the framework
	// pre-populates resp.State with the plan, which would otherwise
	// record changes that never happened.
	applied := state
	applied.GroupS2R = types.StringValue(groupS2R)

	if !plan.Name.Equal(state.Name) {
		_, err := r.client.OrgService.UpdateGroup(ctx, connect.NewRequest(&orgsvcv1.UpdateGroupRequest{
			GroupS2R: groupS2R,
			Name:     plan.Name.ValueString(),
		}))
		if err != nil {
			resp.Diagnostics.Append(resp.State.Set(ctx, &applied)...)
			resp.Diagnostics.AddError("Updating group name", err.Error())

			return
		}
		applied.Name = plan.Name
	}

	current, title, err := r.reconcileMembers(ctx, groupS2R, stateMembers, planMembers)
	if err != nil {
		membersVal, d := types.SetValueFrom(ctx, types.StringType, current)
		resp.Diagnostics.Append(d...)
		applied.Members = membersVal
		resp.Diagnostics.Append(resp.State.Set(ctx, &applied)...)
		resp.Diagnostics.AddError(title, err.Error())

		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *groupResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state groupResourceModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.OrgService.DeleteGroup(ctx, connect.NewRequest(&orgsvcv1.DeleteGroupRequest{
		GroupS2R: state.GroupS2R.ValueString(),
	}))
	if err != nil && connect.CodeOf(err) != connect.CodeNotFound {
		resp.Diagnostics.AddError("Deleting group", err.Error())
	}
}

func (r *groupResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resource.ImportStatePassthroughID(ctx, path.Root("group_s2r"), req, resp)
}

// createGroupShell creates the empty local group. A non-empty groupS2R
// alongside a non-nil error means the group exists server-side but its
// response was unusable; the caller must still record it in state.
func (r *groupResource) createGroupShell(ctx context.Context, name string) (string, string, error) {
	createResp, err := r.client.OrgService.CreateGroup(ctx, connect.NewRequest(&orgsvcv1.CreateGroupRequest{
		OrgS2R: r.client.OrgS2R,
		Name:   name,
		Source: orgsvcv1.GroupSource_GROUP_SOURCE_LOCAL,
	}))
	if err != nil {
		return "", "", err
	}

	g := createResp.Msg.GetGroup()
	if g.GetGroupS2R() == "" {
		return "", "", errEmptyGroup
	}

	src, err := groupSourceToString(g.GetSource())
	if err != nil {
		return g.GetGroupS2R(), "", err
	}

	return g.GetGroupS2R(), src, nil
}

// fetchLocalGroup returns the group and its source string when it
// exists and is locally managed. A nil group with no appended
// diagnostics means the group is gone (NotFound).
func (r *groupResource) fetchLocalGroup(ctx context.Context, groupS2R string, diags *diag.Diagnostics) (*orgsvcv1.Group, string) {
	getResp, err := r.client.OrgService.GetGroup(ctx, connect.NewRequest(&orgsvcv1.GetGroupRequest{
		GroupS2R: groupS2R,
	}))
	if err != nil {
		if connect.CodeOf(err) != connect.CodeNotFound {
			diags.AddError(titleReadingGroup, err.Error())
		}

		return nil, ""
	}

	g := getResp.Msg.GetGroup()
	if g.GetGroupS2R() == "" {
		diags.AddError(titleReadingGroup, "GetGroup returned an empty group for "+groupS2R)

		return nil, ""
	}
	if g.GetSource() != orgsvcv1.GroupSource_GROUP_SOURCE_LOCAL {
		diags.AddError(
			"Group is not locally managed",
			fmt.Sprintf("%s has source %s; only locally-managed groups can be managed by Terraform. "+
				"SCIM groups are owned by the identity provider, and the system Everyone group is implicit.",
				g.GetGroupS2R(), g.GetSource()),
		)

		return nil, ""
	}
	src, err := groupSourceToString(g.GetSource())
	if err != nil {
		diags.AddError(titleReadingGroup, err.Error())

		return nil, ""
	}

	return g, src
}

func (r *groupResource) listMemberPrincipals(ctx context.Context, groupS2R string) ([]string, error) {
	principals := []string{} // non-nil: an empty group is an empty set, not null
	cursor := ""
	for {
		membersResp, err := r.client.OrgService.ListGroupMembers(ctx, connect.NewRequest(&orgsvcv1.ListGroupMembersRequest{
			GroupS2R: groupS2R,
			Cursor:   cursor,
		}))
		if err != nil {
			return nil, err
		}
		for _, m := range membersResp.Msg.GetMembers() {
			p := m.GetPrincipalS2R()
			if p == "" {
				return nil, fmt.Errorf("%w for group %s", errEmptyMemberPrincipal, groupS2R)
			}
			principals = append(principals, p)
		}
		cursor = membersResp.Msg.GetNextCursor()
		if cursor == "" {
			return principals, nil
		}
	}
}

// reconcileMembers applies the membership diff from state to plan:
// additions first (per-principal results, fail closed), then removals.
// The returned slice always reflects the principals that are members
// after the calls that actually succeeded, so error paths can persist
// an accurate state.
func (r *groupResource) reconcileMembers(ctx context.Context, groupS2R string, stateMembers, planMembers []string) ([]string, string, error) {
	toAdd, toRemove := diffMembers(stateMembers, planMembers)

	current := make([]string, 0, len(stateMembers)+len(toAdd))
	current = append(current, stateMembers...)

	if len(toAdd) > 0 {
		addResp, err := r.client.OrgService.AddGroupMembers(ctx, connect.NewRequest(&orgsvcv1.AddGroupMembersRequest{
			GroupS2R:      groupS2R,
			PrincipalS2Rs: toAdd,
		}))
		if err != nil {
			return current, titleAddingMembers, err
		}
		landed, failures := partitionAddResults(addResp.Msg.GetResults())
		current = append(current, landed...)
		if len(failures) > 0 {
			return current, titleAddingMembers,
				fmt.Errorf("%w to group %s:\n%s", errMembersNotAdded, groupS2R, strings.Join(failures, "\n"))
		}
	}

	for _, principal := range toRemove {
		_, err := r.client.OrgService.RemoveGroupMember(ctx, connect.NewRequest(&orgsvcv1.RemoveGroupMemberRequest{
			GroupS2R:     groupS2R,
			PrincipalS2R: principal,
		}))
		// NotFound means the principal is already gone (deleted from the
		// org, or removed out of band) — the desired end state is met, so
		// treat it as a successful removal rather than failing the apply.
		if err != nil && connect.CodeOf(err) != connect.CodeNotFound {
			return current, "Removing group member",
				fmt.Errorf("removing %s from group %s: %w", principal, groupS2R, err)
		}
		remaining := current[:0]
		for _, m := range current {
			if m != principal {
				remaining = append(remaining, m)
			}
		}
		current = remaining
	}

	return current, "", nil
}

// membersFromSet extracts the principal list from a members set; null
// and unknown sets mean no members.
func membersFromSet(ctx context.Context, s types.Set, diags *diag.Diagnostics) []string {
	if s.IsNull() || s.IsUnknown() {
		return nil
	}
	var out []string
	diags.Append(s.ElementsAs(ctx, &out, false)...)

	return out
}

// diffMembers computes the membership changes needed to go from state
// to plan. Output is sorted so API call order is deterministic.
func diffMembers(state, plan []string) ([]string, []string) {
	inState := make(map[string]struct{}, len(state))
	for _, p := range state {
		inState[p] = struct{}{}
	}
	inPlan := make(map[string]struct{}, len(plan))
	for _, p := range plan {
		inPlan[p] = struct{}{}
	}

	var toAdd, toRemove []string
	for p := range inPlan {
		if _, ok := inState[p]; !ok {
			toAdd = append(toAdd, p)
		}
	}
	for p := range inState {
		if _, ok := inPlan[p]; !ok {
			toRemove = append(toRemove, p)
		}
	}
	sort.Strings(toAdd)
	sort.Strings(toRemove)

	return toAdd, toRemove
}

// partitionAddResults splits AddGroupMembers results into principals
// that are now members (AlreadyMember counts as success) and
// per-principal failure descriptions.
func partitionAddResults(results []*orgsvcv1.AddGroupMembersResponse_Result) ([]string, []string) {
	added := make([]string, 0, len(results))
	var failures []string
	for _, res := range results {
		if res.GetError() != "" {
			failures = append(failures, fmt.Sprintf("%s: %s", res.GetPrincipalS2R(), res.GetError()))

			continue
		}
		added = append(added, res.GetPrincipalS2R())
	}

	return added, failures
}
