package vaultres

import (
	"context"
	"fmt"

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
