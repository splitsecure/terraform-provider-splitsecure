package vaultres

import (
	"context"
	"fmt"
	"slices"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	vaultbrowsev1connect "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1/vaultbrowsev1connect"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
)

// Placement is where a record sits: its vault and node, and the folder the plan puts it in.
type Placement struct {
	VaultID  string
	NodeID   string
	Folder   types.List
	FolderID types.String
}

// MoveRecord applies a placement-only update by moving the record under the folder the plan names.
// It refuses an update that changes anything else, since every other input forces replacement.
func MoveRecord(ctx context.Context, req resource.UpdateRequest, browse vaultbrowsev1connect.VaultBrowseServiceClient, p Placement, diags *diag.Diagnostics) bool {
	changed, err := changedBeyondPlacement(req.Plan, req.State)
	if err != nil {
		diags.AddError("Comparing plan and state", err.Error())

		return false
	}

	if changed != "" {
		diags.AddError("Update not supported", fmt.Sprintf("only the folder can change in place, but %q changed too.", changed))

		return false
	}

	parentID, ok := ParentNode(ctx, browse, p.VaultID, p.Folder, p.FolderID, diags)
	if !ok {
		return false
	}

	err = vaultapi.MoveNode(ctx, browse, p.VaultID, p.NodeID, parentID)
	if err != nil {
		diags.AddError("Moving record", err.Error())

		return false
	}

	return true
}

// changedBeyondPlacement names the first input that differs between plan and state, ignoring the placement attributes. Values the plan leaves unknown are skipped.
func changedBeyondPlacement(plan tfsdk.Plan, state tfsdk.State) (string, error) {
	var planVals, stateVals map[string]tftypes.Value

	err := plan.Raw.As(&planVals)
	if err != nil {
		return "", fmt.Errorf("reading plan: %w", err)
	}

	err = state.Raw.As(&stateVals)
	if err != nil {
		return "", fmt.Errorf("reading state: %w", err)
	}

	for _, name := range comparedInputs(plan) {
		if planVals[name].IsFullyKnown() && !planVals[name].Equal(stateVals[name]) {
			return name, nil
		}
	}

	return "", nil
}

// comparedInputs lists the attributes and blocks a user sets, except the placement ones and the write-only create options.
func comparedInputs(plan tfsdk.Plan) []string {
	var names []string

	for name, a := range plan.Schema.GetAttributes() {
		serverOnly := a.IsComputed() && !a.IsOptional() && !a.IsRequired()
		if a.IsWriteOnly() || serverOnly || name == "folder" || name == "folder_id" {
			continue
		}

		names = append(names, name)
	}

	for name := range plan.Schema.GetBlocks() {
		names = append(names, name)
	}

	return names
}

// ObservePlacement returns folder and folder_id as the record sits in the vault now, so a move made elsewhere shows as drift.
// A configured folder_id is refreshed to the parent's node id, and a configured folder path to the parent's label path.
// A record with neither at the root keeps both unset, and elsewhere reports its parent as folder_id.
// When the caller's view hides the path, both values are returned unchanged.
func ObservePlacement(ctx context.Context, browse vaultbrowsev1connect.VaultBrowseServiceClient, vaultID, nodeID string, folder types.List, folderID types.String) (types.List, types.String, error) {
	loc, err := vaultapi.GetNodeLocation(ctx, browse, vaultID, nodeID)
	if err != nil {
		return folder, folderID, err
	}

	parentPath, known := loc.ParentPath()
	if !known {
		return folder, folderID, nil
	}

	if !folder.IsNull() && !folder.IsUnknown() {
		observed, err := observedFolderPath(ctx, folder, parentPath)

		return observed, folderID, err
	}

	parentID, _, err := loc.ParentID(ctx, browse, vaultID)
	if err != nil {
		return folder, folderID, err
	}

	if parentID == "" && folderID.ValueString() == "" {
		return folder, folderID, nil
	}

	return folder, types.StringValue(parentID), nil
}

// observedFolderPath returns the configured path when it matches the parent's, and the parent's path otherwise.
func observedFolderPath(ctx context.Context, configured types.List, parentPath []string) (types.List, error) {
	var want []string

	if diags := configured.ElementsAs(ctx, &want, false); diags.HasError() || slices.Equal(want, parentPath) {
		return configured, nil
	}

	observed, diags := types.ListValueFrom(ctx, types.StringType, parentPath)
	if diags.HasError() {
		return configured, fmt.Errorf("building folder path: %s", diags.Errors()[0].Detail()) //nolint:err113 // diagnostics carry no wrappable error.
	}

	return observed, nil
}
