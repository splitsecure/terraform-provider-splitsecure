package connectedapp

import (
	"context"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	catalog "github.com/splitsecure/terraform-provider-splitsecure/splitsecure/connectedapp"
)

// inputBlocks are the blocks a create reads. A change in any of them replaces the app.
func inputBlocks() []string {
	return []string{"saml2", "oidc", "field", "name_id"}
}

// ModifyPlan keeps the state's input blocks when the plan describes the same app, so the order of field blocks,
// a formatting change of metadata_xml, a field the template fills itself or the default NameID is not a change.
// When the app differs, each changed block replaces the resource.
func (r *appResource) ModifyPlan(ctx context.Context, req resource.ModifyPlanRequest, resp *resource.ModifyPlanResponse) {
	if req.State.Raw.IsNull() || req.Plan.Raw.IsNull() {
		return
	}

	changed, err := changedBlocks(req.Plan.Raw, req.State.Raw)
	if err != nil {
		resp.Diagnostics.AddError("Comparing plan and state", err.Error())

		return
	}

	if len(changed) == 0 {
		return
	}

	if buildInputsKnown(req.Plan.Raw) && sameApp(ctx, req) {
		for _, name := range changed {
			var v types.List

			resp.Diagnostics.Append(req.State.GetAttribute(ctx, path.Root(name), &v)...)
			resp.Diagnostics.Append(resp.Plan.SetAttribute(ctx, path.Root(name), v)...)
		}

		return
	}

	for _, name := range changed {
		resp.RequiresReplace = append(resp.RequiresReplace, path.Root(name))
	}
}

// changedBlocks names the input blocks whose plan value differs from the state's.
func changedBlocks(plan, state tftypes.Value) ([]string, error) {
	var planVals, stateVals map[string]tftypes.Value

	err := plan.As(&planVals)
	if err != nil {
		return nil, fmt.Errorf("reading plan: %w", err)
	}

	err = state.As(&stateVals)
	if err != nil {
		return nil, fmt.Errorf("reading state: %w", err)
	}

	var out []string

	for _, name := range inputBlocks() {
		if !planVals[name].Equal(stateVals[name]) {
			out = append(out, name)
		}
	}

	return out, nil
}

// sameApp reports whether plan and state build the same app.
func sameApp(ctx context.Context, req resource.ModifyPlanRequest) bool {
	var plan, state appModel

	if req.Plan.Get(ctx, &plan).HasError() || req.State.Get(ctx, &state).HasError() {
		return false
	}

	if plan.Template.ValueString() != state.Template.ValueString() {
		return false
	}

	t, err := catalog.Lookup(plan.Template.ValueString())
	if err != nil {
		return false
	}

	planned, diags := params(ctx, &plan)
	if diags.HasError() {
		return false
	}

	stated, diags := params(ctx, &state)
	if diags.HasError() {
		return false
	}

	return canonicalOf(t, planned).equal(canonicalOf(t, stated))
}

// reconcileInputs keeps the state's input blocks when they build the app the record holds, and otherwise sets them
// from the record, as after an import or when the record differs. It refuses a record the schema cannot express.
func reconcileInputs(ctx context.Context, m *appModel, app *pb.ConnectedAppParams) error {
	t, err := catalog.Lookup(app.GetTemplate())
	if err != nil {
		return fmt.Errorf("%w: %w", errUnexpressible, err)
	}

	recorded, err := recordAsCreate(app)
	if err != nil {
		return err
	}

	want := canonicalOf(t, recorded)

	if hasInputs(m) && buildsTo(ctx, m, t, want) {
		return nil
	}

	in, err := inputsFromRecord(ctx, t, app)
	if err != nil {
		return err
	}

	rebuilt := *m
	rebuilt.SAML2, rebuilt.OIDC, rebuilt.Fields, rebuilt.NameID = in.saml2, in.oidc, in.fields, in.nameID

	if !buildsTo(ctx, &rebuilt, t, want) {
		return fmt.Errorf("%w: rebuilding the record's fields and layout does not give back the same app", errUnexpressible)
	}

	*m = rebuilt

	return nil
}

// hasInputs reports whether the model holds input blocks, which an import leaves unset.
func hasInputs(m *appModel) bool {
	return !m.SAML2.IsNull() && !m.OIDC.IsNull() && !m.Fields.IsNull()
}

func buildsTo(ctx context.Context, m *appModel, t *catalog.Template, want *canonical) bool {
	built, diags := params(ctx, m)
	if diags.HasError() {
		return false
	}

	return canonicalOf(t, built).equal(want)
}
