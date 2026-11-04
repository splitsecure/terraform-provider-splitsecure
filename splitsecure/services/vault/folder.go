package vault

import (
	"context"
	"fmt"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultres"
)

var (
	_ resource.Resource                = (*folderResource)(nil)
	_ resource.ResourceWithImportState = (*folderResource)(nil)
)

type folderResource struct {
	client *client.Client
}

type folderModel struct {
	ID       types.String `tfsdk:"id"`
	VaultID  types.String `tfsdk:"vault_id"`
	Name     types.String `tfsdk:"name"`
	ParentID types.String `tfsdk:"parent_id"`
}

// NewFolderResource returns a factory for the splitsecure_vault_folder resource.
func NewFolderResource() resource.Resource {
	return &folderResource{}
}

func (r *folderResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_vault_folder"
}

func (r *folderResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = vaultres.ClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *folderResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Folder in a vault. Deleting it moves any children into the vault's lost+found folder and never destroys records.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Node id of the folder. Also the import id as vault_id/id.",
				PlanModifiers: vaultres.ComputedOnce(),
			},
			"vault_id": schema.StringAttribute{
				Required:      true,
				Description:   "Vault the folder is in. Changing it replaces the resource.",
				PlanModifiers: vaultres.ForceNew(),
				Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Folder name. Must be unique among its siblings. Changing it renames the folder in place.",
				Validators:  []validator.String{stringvalidator.LengthBetween(1, 256)},
			},
			"parent_id": schema.StringAttribute{
				Optional:    true,
				Description: "Node id of the parent folder. Unset places the folder at the vault root. Changing it moves the folder in place.",
			},
		},
	}
}

func (r *folderResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan folderModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	created, err := r.client.VaultBrowse.CreateFolder(ctx, connect.NewRequest(&vaultbrowsev1.CreateFolderRequest{
		Base: &vaultbrowsev1.CreateFolderRequest_Base{
			VaultId: plan.VaultID.ValueString(),
			Label:   plan.Name.ValueString(),
			Locator: nodeLocator(plan.ParentID.ValueString()),
		},
	}))
	if err != nil {
		resp.Diagnostics.AddError("Creating folder", err.Error())

		return
	}

	plan.ID = types.StringValue(created.Msg.GetNodeId())

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *folderResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state folderModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	vaultID := state.VaultID.ValueString()

	loc, err := vaultapi.GetNodeLocation(ctx, r.client.VaultBrowse, vaultID, state.ID.ValueString())
	if vaultapi.IsNotFound(err) {
		resp.State.RemoveResource(ctx)

		return
	}

	if err != nil {
		resp.Diagnostics.AddError("Reading folder", err.Error())

		return
	}

	state.Name = types.StringValue(loc.Node.GetLabel())

	parentID, known, err := loc.ParentID(ctx, r.client.VaultBrowse, vaultID)
	if err != nil {
		resp.Diagnostics.AddError("Reading folder parent", err.Error())

		return
	}

	if known {
		state.ParentID = parentValue(parentID, state.ParentID)
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *folderResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state folderModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	vaultID := state.VaultID.ValueString()
	id := state.ID.ValueString()

	if plan.Name.ValueString() != state.Name.ValueString() {
		_, err := r.client.VaultBrowse.RenameNode(ctx, connect.NewRequest(&vaultbrowsev1.RenameNodeRequest{
			Base: &vaultbrowsev1.RenameNodeRequest_Base{VaultId: vaultID, NodeId: id, NewLabel: plan.Name.ValueString()},
		}))
		if err != nil {
			resp.Diagnostics.AddError("Renaming folder", err.Error())

			return
		}
	}

	if plan.ParentID.ValueString() != state.ParentID.ValueString() {
		_, err := r.client.VaultBrowse.MoveNode(ctx, connect.NewRequest(&vaultbrowsev1.MoveNodeRequest{
			Base: &vaultbrowsev1.MoveNodeRequest_Base{VaultId: vaultID, NodeId: id, Locator: nodeLocator(plan.ParentID.ValueString())},
		}))
		if err != nil {
			resp.Diagnostics.AddError("Moving folder", err.Error())

			return
		}
	}

	plan.ID = state.ID

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *folderResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state folderModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.VaultBrowse.DeleteFolder(ctx, connect.NewRequest(&vaultbrowsev1.DeleteFolderRequest{
		Base: &vaultbrowsev1.DeleteFolderRequest_Base{VaultId: state.VaultID.ValueString(), Locator: nodeLocator(state.ID.ValueString())},
	}))
	if err != nil && !vaultapi.IsNotFound(err) {
		resp.Diagnostics.AddError("Deleting folder", err.Error())
	}
}

func (r *folderResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	vaultID, id, ok := vaultres.SplitImportID(req.ID)
	if !ok {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("expected vault_id/id, got %q", req.ID))

		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vault_id"), vaultID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

// nodeLocator names a node by id. The server reads the parent_node_id arm as the node itself on GetNode and DeleteFolder, and as the parent elsewhere. An empty id leaves the locator unset.
func nodeLocator(nodeID string) *vaultbrowsev1.NodeLocator {
	if nodeID == "" {
		return nil
	}

	return &vaultbrowsev1.NodeLocator{Union: &vaultbrowsev1.NodeLocator_ParentNodeId{ParentNodeId: nodeID}}
}

// parentValue maps the live parent to state. A root parent keeps an unset parent_id null and an empty one empty.
func parentValue(parentID string, prior types.String) types.String {
	if parentID != "" {
		return types.StringValue(parentID)
	}

	if prior.IsNull() || prior.IsUnknown() {
		return types.StringNull()
	}

	return types.StringValue("")
}
