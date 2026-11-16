package connectedapp

import (
	"context"
	"errors"
	"fmt"

	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	catalog "github.com/splitsecure/terraform-provider-splitsecure/splitsecure/connectedapp"
)

var errInputsDiffer = errors.New("the field, saml2, oidc and name_id blocks build a different app than the record holds")

// inputBlocks are the blocks a create reads. A change in any of them replaces the app.
func inputBlocks() []string {
	return []string{"saml2", "oidc", "field", "name_id"}
}

// ModifyPlan replaces the resource when a changed input block builds a different app. A change that builds the same
// app, such as reordered field blocks, a reformatted metadata_xml, a field the template fills itself or the default
// NameID, plans an in-place update that changes nothing on the server.
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

	if buildInputsKnown(req.Plan.Raw) {
		var plan, state appModel

		resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
		resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

		if resp.Diagnostics.HasError() || sameApp(ctx, &plan, &state) {
			return
		}
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
func sameApp(ctx context.Context, plan, state *appModel) bool {
	if plan.Template.ValueString() != state.Template.ValueString() {
		return false
	}

	t, err := catalog.Lookup(plan.Template.ValueString())
	if err != nil {
		return false
	}

	planned, diags := params(ctx, plan)
	if diags.HasError() {
		return false
	}

	stated, diags := params(ctx, state)
	if diags.HasError() {
		return false
	}

	return canonicalOf(t, planned).equal(canonicalOf(t, stated))
}

// inputsBuildRecord reports why the model's input blocks do not build the app the record holds, or nil when they do.
func inputsBuildRecord(ctx context.Context, m *appModel, app *pb.ConnectedAppParams) error {
	t, want, err := recordCanonical(app)
	if err != nil {
		return err
	}

	if !buildsTo(ctx, m, t, want) {
		return errInputsDiffer
	}

	return nil
}

// importInputs sets the model's input blocks from the record, as after an import. It refuses a record the schema
// cannot express.
func importInputs(ctx context.Context, m *appModel, app *pb.ConnectedAppParams) error {
	t, want, err := recordCanonical(app)
	if err != nil {
		return err
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

func recordCanonical(app *pb.ConnectedAppParams) (*catalog.Template, *canonical, error) {
	t, err := catalog.Lookup(app.GetTemplate())
	if err != nil {
		return nil, nil, fmt.Errorf("%w: %w", errUnexpressible, err)
	}

	recorded, err := recordAsCreate(app)
	if err != nil {
		return nil, nil, err
	}

	return t, canonicalOf(t, recorded), nil
}

// hasInputs reports whether the model holds a binding block, which every config sets and an import leaves unset.
func hasInputs(m *appModel) bool {
	return !m.SAML2.IsNull() || !m.OIDC.IsNull()
}

func buildsTo(ctx context.Context, m *appModel, t *catalog.Template, want *canonical) bool {
	built, diags := params(ctx, m)
	if diags.HasError() {
		return false
	}

	return canonicalOf(t, built).equal(want)
}
