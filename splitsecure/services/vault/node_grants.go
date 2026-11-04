package vault

import (
	"context"
	"errors"
	"fmt"
	"sort"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	authzv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/authz/v1"
	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultres"
)

var (
	_ resource.Resource                = (*nodeGrantsResource)(nil)
	_ resource.ResourceWithImportState = (*nodeGrantsResource)(nil)
)

var (
	errDuplicateGrantee = errors.New("a grantee appears in more than one grant block")
	errBadBlocks        = errors.New("reading grant blocks")
)

type nodeGrantsResource struct {
	client *client.Client
}

type nodeGrantsModel struct {
	ID      types.String `tfsdk:"id"`
	VaultID types.String `tfsdk:"vault_id"`
	NodeID  types.String `tfsdk:"node_id"`
	Grant   types.Set    `tfsdk:"grant"`
}

type nodeGrantModel struct {
	Grantee types.String `tfsdk:"grantee"`
	Tier    types.String `tfsdk:"tier"`
}

func nodeGrantType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{"grantee": types.StringType, "tier": types.StringType}}
}

// NewNodeGrantsResource returns a factory for the splitsecure_vault_node_grants resource.
func NewNodeGrantsResource() resource.Resource {
	return &nodeGrantsResource{}
}

func (r *nodeGrantsResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_vault_node_grants"
}

func (r *nodeGrantsResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = vaultres.ClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *nodeGrantsResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Authoritative set of direct grants on one vault folder or record. Applying it makes the node's direct grants equal the grant blocks: " +
			"missing grants are added, tiers are changed, and every other direct grant is removed. " +
			"The grant of the service account Terraform signs in as is always kept, and grants inherited from parent folders are not touched. " +
			"Destroying it removes the declared grants only. Import with vault_id/node_id.\n\n" +
			"Choosing a resource: this resource owns every direct grant on the node. " +
			"Use splitsecure_vault_grant instead to add one grant and leave the others alone. " +
			"Never use both on the same node.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Resource id in the form vault_id/node_id.",
				PlanModifiers: vaultres.ComputedOnce(),
			},
			"vault_id": schema.StringAttribute{
				Required:      true,
				Description:   "Vault the node is in. Changing it replaces the resource.",
				PlanModifiers: vaultres.ForceNew(),
				Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"node_id": schema.StringAttribute{
				Required:      true,
				Description:   "Node id of the folder or record. A record's id is its node id. Changing it replaces the resource.",
				PlanModifiers: vaultres.ForceNew(),
				Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
			},
		},
		Blocks: map[string]schema.Block{
			"grant": schema.SetNestedBlock{
				Description: "One grantee and its tier. List every grantee that should have a direct grant.",
				NestedObject: schema.NestedBlockObject{
					Attributes: map[string]schema.Attribute{
						"grantee": schema.StringAttribute{
							Required:    true,
							Description: "Full s2r of the principal, service account or group.",
							Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
						},
						"tier": schema.StringAttribute{
							Required:    true,
							Description: "Access tier, one of: view, use, edit.",
							Validators:  []validator.String{stringvalidator.OneOf(tierView, tierUse, tierEdit)},
						},
					},
				},
			},
		},
	}
}

func (r *nodeGrantsResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan nodeGrantsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	applyGrants(ctx, r.client, &plan, &resp.Diagnostics)

	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(plan.VaultID.ValueString() + "/" + plan.NodeID.ValueString())

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *nodeGrantsResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan nodeGrantsModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	applyGrants(ctx, r.client, &plan, &resp.Diagnostics)

	if resp.Diagnostics.HasError() {
		return
	}

	plan.ID = types.StringValue(plan.VaultID.ValueString() + "/" + plan.NodeID.ValueString())

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// apply makes the node's direct grants equal the plan, keeping the caller's own grant.
func applyGrants(ctx context.Context, c *client.Client, plan *nodeGrantsModel, diags *diag.Diagnostics) {
	declared, err := declaredGrants(ctx, plan.Grant)
	if err != nil {
		diags.AddError("Reading grant blocks", err.Error())

		return
	}

	vaultID, nodeID := plan.VaultID.ValueString(), plan.NodeID.ValueString()

	current, err := listGrants(ctx, c, vaultID, nodeID)
	if err != nil {
		diags.AddError("Applying grants", err.Error())

		return
	}

	err = putChanged(ctx, c, vaultID, nodeID, declared, current)
	if err != nil {
		diags.AddError("Applying grants", err.Error())

		return
	}

	for _, g := range current {
		_, wanted := declared[g.GetGranteeId()]
		if wanted || g.GetGranteeId() == c.PrincipalS2R {
			continue
		}

		err = deleteGrant(ctx, c, vaultID, nodeID, g.GetGranteeId(), g.GetIdpId())
		if err != nil {
			diags.AddError("Removing grant", err.Error())

			return
		}
	}
}

// putChanged writes the declared grants that are missing or at another tier, one PutGrants call per tier.
func putChanged(ctx context.Context, c *client.Client, vaultID, nodeID string, declared map[string]string, current []*vaultbrowsev1.Grant) error {
	have := make(map[string]authzv1.Tier, len(current))
	for _, g := range current {
		have[g.GetGranteeId()] = g.GetTier()
	}

	byTier := map[string][]string{}

	for grantee, tier := range declared {
		if have[grantee] != tierToProto(tier) {
			byTier[tier] = append(byTier[tier], grantee)
		}
	}

	for tier, grantees := range byTier {
		sort.Strings(grantees)

		_, err := c.VaultBrowse.PutGrants(ctx, connect.NewRequest(&vaultbrowsev1.PutGrantsRequest{
			Base: &vaultbrowsev1.PutGrantsRequest_Base{VaultId: vaultID, NodeId: nodeID, GranteeIds: grantees, Tier: tierToProto(tier)},
		}))
		if err != nil {
			return fmt.Errorf("putting %s grants: %w", tier, err)
		}
	}

	return nil
}

func (r *nodeGrantsResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state nodeGrantsModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	current, err := listGrants(ctx, r.client, state.VaultID.ValueString(), state.NodeID.ValueString())
	if vaultapi.IsNotFound(err) {
		resp.State.RemoveResource(ctx)

		return
	}

	if err != nil {
		resp.Diagnostics.AddError("Reading grants", err.Error())

		return
	}

	declared, err := declaredGrants(ctx, state.Grant)
	if err != nil {
		resp.Diagnostics.AddError("Reading grant blocks", err.Error())

		return
	}

	elems := make([]nodeGrantModel, 0, len(current))

	for _, g := range current {
		_, inState := declared[g.GetGranteeId()]
		if g.GetGranteeId() == r.client.PrincipalS2R && !inState {
			continue
		}

		elems = append(elems, nodeGrantModel{Grantee: types.StringValue(g.GetGranteeId()), Tier: types.StringValue(tierFromProto(g.GetTier()))})
	}

	set, diags := types.SetValueFrom(ctx, nodeGrantType(), elems)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	state.Grant = set
	state.ID = types.StringValue(state.VaultID.ValueString() + "/" + state.NodeID.ValueString())

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *nodeGrantsResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state nodeGrantsModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	declared, err := declaredGrants(ctx, state.Grant)
	if err != nil {
		resp.Diagnostics.AddError("Reading grant blocks", err.Error())

		return
	}

	for grantee := range declared {
		if grantee == r.client.PrincipalS2R {
			continue
		}

		err = deleteGrant(ctx, r.client, state.VaultID.ValueString(), state.NodeID.ValueString(), grantee, "")
		if err != nil {
			resp.Diagnostics.AddError("Removing grant", err.Error())

			return
		}
	}
}

func (r *nodeGrantsResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	vaultID, nodeID, ok := vaultres.SplitImportID(req.ID)
	if !ok {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("expected vault_id/node_id, got %q", req.ID))

		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vault_id"), vaultID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("node_id"), nodeID)...)
}

// declaredGrants maps each declared grantee to its tier and refuses a grantee declared twice.
func declaredGrants(ctx context.Context, set types.Set) (map[string]string, error) {
	var blocks []nodeGrantModel

	diags := set.ElementsAs(ctx, &blocks, false)
	if diags.HasError() {
		return nil, fmt.Errorf("%w: %s", errBadBlocks, diags.Errors()[0].Detail())
	}

	declared := make(map[string]string, len(blocks))

	for _, b := range blocks {
		if _, dup := declared[b.Grantee.ValueString()]; dup {
			return nil, fmt.Errorf("%w: %s", errDuplicateGrantee, b.Grantee.ValueString())
		}

		declared[b.Grantee.ValueString()] = b.Tier.ValueString()
	}

	return declared, nil
}

func deleteGrant(ctx context.Context, c *client.Client, vaultID, nodeID, grantee, idpID string) error {
	_, err := c.VaultBrowse.DeleteGrant(ctx, connect.NewRequest(&vaultbrowsev1.DeleteGrantRequest{
		Base: &vaultbrowsev1.DeleteGrantRequest_Base{VaultId: vaultID, NodeId: nodeID, GranteeId: grantee, IdpId: idpID},
	}))
	if err != nil && !vaultapi.IsNotFound(err) {
		return fmt.Errorf("deleting grant of %s: %w", grantee, err)
	}

	return nil
}
