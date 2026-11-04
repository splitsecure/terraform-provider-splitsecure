package vault

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
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
	_ resource.Resource                = (*grantResource)(nil)
	_ resource.ResourceWithImportState = (*grantResource)(nil)
)

const (
	tierView = "view"
	tierUse  = "use"
	tierEdit = "edit"

	// directoryIDPID is the identity provider the server stamps on grants to deployment directory principals.
	directoryIDPID = "s2:directory"
)

type grantResource struct {
	client *client.Client
}

type grantModel struct {
	ID      types.String `tfsdk:"id"`
	VaultID types.String `tfsdk:"vault_id"`
	NodeID  types.String `tfsdk:"node_id"`
	Grantee types.String `tfsdk:"grantee"`
	Tier    types.String `tfsdk:"tier"`
	IDPID   types.String `tfsdk:"idp_id"`
}

// NewGrantResource returns a factory for the splitsecure_vault_grant resource.
func NewGrantResource() resource.Resource {
	return &grantResource{}
}

func (r *grantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_vault_grant"
}

func (r *grantResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = vaultres.ClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *grantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Grant of one grantee on a vault folder or record. Import with vault_id/node_id/grantee, where grantee is the full s2r of the principal or group.\n\n" +
			"Choosing a resource: this resource is additive. It adds, changes and removes only its own grant and leaves every other grant on the node alone. " +
			"Use splitsecure_vault_node_grants instead to own every direct grant on the node. " +
			"Never use both on the same node.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Grant id in the form vault_id/node_id/grantee.",
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
				Description:   "Node id of the folder or record to grant on. A record's id is its node id. Changing it replaces the resource.",
				PlanModifiers: vaultres.ForceNew(),
				Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"grantee": schema.StringAttribute{
				Required:      true,
				Description:   "Full s2r of the principal, service account or group to grant to. Changing it replaces the resource.",
				PlanModifiers: vaultres.ForceNew(),
				Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"tier": schema.StringAttribute{
				Required:    true,
				Description: "Access tier, one of: view, use, edit. Changing it updates the grant in place.",
				Validators:  []validator.String{stringvalidator.OneOf(tierView, tierUse, tierEdit)},
			},
			"idp_id": schema.StringAttribute{
				Optional:      true,
				Description:   "Identity provider of the grantee. Unset means the deployment directory. Changing it replaces the resource.",
				PlanModifiers: vaultres.ForceNew(),
			},
		},
	}
}

func (r *grantResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan grantModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	err := putGrant(ctx, r.client, &plan)
	if err != nil {
		resp.Diagnostics.AddError("Creating grant", err.Error())

		return
	}

	plan.ID = types.StringValue(grantID(&plan))

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *grantResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan grantModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	err := putGrant(ctx, r.client, &plan)
	if err != nil {
		resp.Diagnostics.AddError("Updating grant", err.Error())

		return
	}

	plan.ID = types.StringValue(grantID(&plan))

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func putGrant(ctx context.Context, c *client.Client, m *grantModel) error {
	_, err := c.VaultBrowse.PutGrants(ctx, connect.NewRequest(&vaultbrowsev1.PutGrantsRequest{
		Base: &vaultbrowsev1.PutGrantsRequest_Base{
			VaultId:    m.VaultID.ValueString(),
			NodeId:     m.NodeID.ValueString(),
			GranteeIds: []string{m.Grantee.ValueString()},
			Tier:       tierToProto(m.Tier.ValueString()),
			IdpId:      m.IDPID.ValueString(),
		},
	}))
	if err != nil {
		return fmt.Errorf("putting grant: %w", err)
	}

	return nil
}

func (r *grantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state grantModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	found, err := findGrant(ctx, r.client, &state)
	if vaultapi.IsNotFound(err) || (err == nil && found == nil) {
		resp.State.RemoveResource(ctx)

		return
	}

	if err != nil {
		resp.Diagnostics.AddError("Reading grant", err.Error())

		return
	}

	state.Tier = types.StringValue(tierFromProto(found.GetTier()))
	state.ID = types.StringValue(grantID(&state))

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// listGrants pages through the direct grants on a node.
func listGrants(ctx context.Context, c *client.Client, vaultID, nodeID string) ([]*vaultbrowsev1.Grant, error) {
	var (
		all    []*vaultbrowsev1.Grant
		cursor []byte
	)

	for {
		resp, err := c.VaultBrowse.ListGrants(ctx, connect.NewRequest(&vaultbrowsev1.ListGrantsRequest{
			Base: &vaultbrowsev1.ListGrantsRequest_Base{VaultId: vaultID, NodeId: nodeID, PageParams: pageAt(cursor)},
		}))
		if err != nil {
			return nil, fmt.Errorf("listing grants: %w", err)
		}

		all = append(all, resp.Msg.GetGrants()...)

		cursor = resp.Msg.GetNextCursor()
		if len(cursor) == 0 {
			return all, nil
		}
	}
}

// findGrant returns the grantee's direct grant on the node, or nil when it has none.
func findGrant(ctx context.Context, c *client.Client, m *grantModel) (*vaultbrowsev1.Grant, error) {
	grants, err := listGrants(ctx, c, m.VaultID.ValueString(), m.NodeID.ValueString())
	if err != nil {
		return nil, err
	}

	for _, g := range grants {
		if g.GetGranteeId() == m.Grantee.ValueString() && sameIDP(g.GetIdpId(), m.IDPID.ValueString()) {
			return g, nil
		}
	}

	return nil, nil //nolint:nilnil // no grant is a normal answer, not an error.
}

func (r *grantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state grantModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.VaultBrowse.DeleteGrant(ctx, connect.NewRequest(&vaultbrowsev1.DeleteGrantRequest{
		Base: &vaultbrowsev1.DeleteGrantRequest_Base{
			VaultId:   state.VaultID.ValueString(),
			NodeId:    state.NodeID.ValueString(),
			GranteeId: state.Grantee.ValueString(),
			IdpId:     state.IDPID.ValueString(),
		},
	}))
	if err != nil && !vaultapi.IsNotFound(err) {
		resp.Diagnostics.AddError("Deleting grant", err.Error())
	}
}

func (r *grantResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	vaultID, nodeID, grantee, ok := splitGrantImportID(req.ID)
	if !ok {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("expected vault_id/node_id/grantee, got %q", req.ID))

		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vault_id"), vaultID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("node_id"), nodeID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("grantee"), grantee)...)
}

// splitGrantImportID splits vault_id/node_id/grantee. The grantee keeps any slashes of its own, as group s2rs have one.
func splitGrantImportID(raw string) (string, string, string, bool) {
	parts := strings.SplitN(raw, "/", 3)
	if len(parts) != 3 || parts[0] == "" || parts[1] == "" || parts[2] == "" {
		return "", "", "", false
	}

	return parts[0], parts[1], parts[2], true
}

func grantID(m *grantModel) string {
	return m.VaultID.ValueString() + "/" + m.NodeID.ValueString() + "/" + m.Grantee.ValueString()
}

// sameIDP treats an unset identity provider and the deployment directory as one, as the server stamps grants with the latter.
func sameIDP(listed, configured string) bool {
	if configured == "" {
		return listed == "" || listed == directoryIDPID
	}

	return listed == configured
}

func tierToProto(tier string) authzv1.Tier {
	switch tier {
	case tierView:
		return authzv1.Tier_TIER_VIEW
	case tierUse:
		return authzv1.Tier_TIER_USE
	case tierEdit:
		return authzv1.Tier_TIER_EDIT
	default:
		return authzv1.Tier_TIER_UNSPECIFIED
	}
}

func tierFromProto(tier authzv1.Tier) string {
	switch tier {
	case authzv1.Tier_TIER_VIEW:
		return tierView
	case authzv1.Tier_TIER_USE:
		return tierUse
	case authzv1.Tier_TIER_EDIT:
		return tierEdit
	case authzv1.Tier_TIER_UNSPECIFIED:
		return ""
	default:
		return ""
	}
}
