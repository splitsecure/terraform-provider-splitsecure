package vault

import (
	"cmp"
	"context"
	"errors"
	"fmt"
	"slices"
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
	errDuplicateGrantee = errors.New("a grantee and identity provider appear in more than one grant block")
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
	IDPID   types.String `tfsdk:"idp_id"`
}

// grantKey identifies a direct grant: one grantee under one identity provider.
type grantKey struct {
	grantee string
	idp     string
}

func newGrantKey(grantee, idp string) grantKey {
	return grantKey{grantee: grantee, idp: normalizeIDP(idp)}
}

func nodeGrantType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{"grantee": types.StringType, "tier": types.StringType, "idp_id": types.StringType}}
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
			"The grant of the service account Terraform signs in as is kept, and grants inherited from parent folders are not touched. " +
			"A group grant that gives Terraform its own access is removed unless a grant block declares it. " +
			"A grant block for the service account Terraform signs in as must have the edit tier. " +
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
				Description: "One grantee, its identity provider and its tier. List every grant the node should have.",
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
						"idp_id": schema.StringAttribute{
							Optional:    true,
							Description: "Identity provider of the grantee. Unset means the deployment directory. A grantee can have one grant per identity provider.",
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

// applyGrants makes the node's direct grants equal the plan, keeping the caller's own grant.
// Removals run before writes, and nothing is written when the plan would lower the caller's own grant.
func applyGrants(ctx context.Context, c *client.Client, plan *nodeGrantsModel, diags *diag.Diagnostics) {
	declared, err := declaredGrants(ctx, plan.Grant)
	if err != nil {
		diags.AddError("Reading grant blocks", err.Error())

		return
	}

	if ownGrantBelowEdit(declared, c.PrincipalS2R) {
		diags.AddAttributeError(path.Root("grant"), "Refusing to lower the provider's own grant",
			c.PrincipalS2R+" is the service account Terraform signs in as. Its grant must stay at the edit tier or Terraform loses access to the node.")

		return
	}

	vaultID, nodeID := plan.VaultID.ValueString(), plan.NodeID.ValueString()

	current, err := listGrants(ctx, c, vaultID, nodeID)
	if err != nil {
		diags.AddError("Applying grants", err.Error())

		return
	}

	for _, g := range current {
		_, wanted := declared[newGrantKey(g.GetGranteeId(), g.GetIdpId())]
		if wanted || g.GetGranteeId() == c.PrincipalS2R {
			continue
		}

		err = deleteGrant(ctx, c, vaultID, nodeID, g.GetGranteeId(), g.GetIdpId())
		if err != nil {
			diags.AddError("Removing grant", err.Error())

			return
		}
	}

	err = putChanged(ctx, c, vaultID, nodeID, declared, current)
	if err != nil {
		diags.AddError("Applying grants", err.Error())
	}
}

func ownGrantBelowEdit(declared map[grantKey]nodeGrantModel, principal string) bool {
	for key, g := range declared {
		if key.grantee == principal && g.Tier.ValueString() != tierEdit {
			return true
		}
	}

	return false
}

// putChanged writes the declared grants that are missing or at another tier, one PutGrants call per tier and identity provider.
func putChanged(ctx context.Context, c *client.Client, vaultID, nodeID string, declared map[grantKey]nodeGrantModel, current []*vaultbrowsev1.Grant) error {
	have := make(map[grantKey]authzv1.Tier, len(current))
	for _, g := range current {
		have[newGrantKey(g.GetGranteeId(), g.GetIdpId())] = g.GetTier()
	}

	type batch struct{ tier, idp string }

	batches := map[batch][]string{}

	for key, g := range declared {
		if have[key] != tierToProto(g.Tier.ValueString()) {
			b := batch{tier: g.Tier.ValueString(), idp: g.IDPID.ValueString()}
			batches[b] = append(batches[b], key.grantee)
		}
	}

	order := make([]batch, 0, len(batches))
	for b := range batches {
		order = append(order, b)
	}

	slices.SortFunc(order, func(a, b batch) int { return cmp.Or(cmp.Compare(a.tier, b.tier), cmp.Compare(a.idp, b.idp)) })

	for _, b := range order {
		grantees := batches[b]
		sort.Strings(grantees)

		_, err := c.VaultBrowse.PutGrants(ctx, connect.NewRequest(&vaultbrowsev1.PutGrantsRequest{
			Base: &vaultbrowsev1.PutGrantsRequest_Base{VaultId: vaultID, NodeId: nodeID, GranteeIds: grantees, Tier: tierToProto(b.tier), IdpId: b.idp},
		}))
		if err != nil {
			return fmt.Errorf("putting %s grants: %w", b.tier, err)
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
		key := newGrantKey(g.GetGranteeId(), g.GetIdpId())

		kept, inState := declared[key]
		if g.GetGranteeId() == r.client.PrincipalS2R && !inState {
			continue
		}

		elems = append(elems, nodeGrantModel{Grantee: types.StringValue(g.GetGranteeId()), Tier: types.StringValue(tierFromProto(g.GetTier())), IDPID: observedIDP(key, kept, inState)})
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

// observedIDP keeps the identity provider as written for a declared grant and reports the directory as null.
func observedIDP(key grantKey, declared nodeGrantModel, inState bool) types.String {
	switch {
	case inState:
		return declared.IDPID
	case key.idp != "":
		return types.StringValue(key.idp)
	default:
		return types.StringNull()
	}
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

	for key, g := range declared {
		if key.grantee == r.client.PrincipalS2R {
			continue
		}

		err = deleteGrant(ctx, r.client, state.VaultID.ValueString(), state.NodeID.ValueString(), key.grantee, g.IDPID.ValueString())
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

// declaredGrants maps each declared grant by grantee and identity provider and refuses a pair declared twice.
func declaredGrants(ctx context.Context, set types.Set) (map[grantKey]nodeGrantModel, error) {
	var blocks []nodeGrantModel

	diags := set.ElementsAs(ctx, &blocks, false)
	if diags.HasError() {
		return nil, fmt.Errorf("%w: %s", errBadBlocks, diags.Errors()[0].Detail())
	}

	declared := make(map[grantKey]nodeGrantModel, len(blocks))

	for _, b := range blocks {
		key := newGrantKey(b.Grantee.ValueString(), b.IDPID.ValueString())
		if _, dup := declared[key]; dup {
			return nil, fmt.Errorf("%w: %s", errDuplicateGrantee, b.Grantee.ValueString())
		}

		declared[key] = b
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
