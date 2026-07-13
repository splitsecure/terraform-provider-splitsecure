package org

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"time"

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

	authzv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/authz/v1"
	orgsvcv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/orgsvc/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

var (
	_ resource.Resource                = (*grantResource)(nil)
	_ resource.ResourceWithImportState = (*grantResource)(nil)
)

type grantResource struct {
	client *client.Client
}

type grantModel struct {
	ResourceS2R types.String `tfsdk:"resource_s2r"`
	GranteeS2R  types.String `tfsdk:"grantee_s2r"`
	Tier        types.String `tfsdk:"tier"`
}

// NewGrant returns a factory for the per-resource permission grant
// resource.
func NewGrant() resource.Resource {
	return &grantResource{}
}

func (r *grantResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_grant"
}

func (r *grantResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *grantResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Permission grant giving a principal (user, service account, or group) a tier on a resource. " +
			"Keyed by (resource, grantee) within the provider-configured org; only the tier can change in place.",
		Attributes: map[string]schema.Attribute{
			"resource_s2r": schema.StringAttribute{
				Required:      true,
				Description:   "s2r URI of the resource being shared.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"grantee_s2r": schema.StringAttribute{
				Required:      true,
				Description:   "s2r URI of the principal receiving access: a user, service account, or group.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.RequiresReplace()},
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"tier": schema.StringAttribute{
				Required:    true,
				Description: "Access tier. One of: " + strings.Join(tierValues(), ", ") + ".",
				Validators: []validator.String{
					stringvalidator.OneOf(tierValues()...),
				},
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

	resp.Diagnostics.Append(r.upsertGrant(ctx, plan, true)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *grantResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	getResp, err := r.client.OrgService.GetGrant(ctx, connect.NewRequest(&orgsvcv1.GetGrantRequest{
		OrgS2R:      r.client.OrgS2R,
		ResourceS2R: state.ResourceS2R.ValueString(),
		GranteeS2R:  state.GranteeS2R.ValueString(),
	}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			resp.State.RemoveResource(ctx)

			return
		}
		resp.Diagnostics.AddError("Reading grant", err.Error())

		return
	}

	resp.Diagnostics.Append(populateGrantModel(&state, getResp.Msg.GetGrant())...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *grantResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan grantModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(r.upsertGrant(ctx, plan, false)...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *grantResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state grantModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	_, err := r.client.OrgService.DeleteGrant(ctx, connect.NewRequest(&orgsvcv1.DeleteGrantRequest{
		OrgS2R:      r.client.OrgS2R,
		ResourceS2R: state.ResourceS2R.ValueString(),
		GranteeS2R:  state.GranteeS2R.ValueString(),
	}))
	if err != nil && connect.CodeOf(err) != connect.CodeNotFound {
		resp.Diagnostics.AddError("Deleting grant", err.Error())
	}
}

func (r *grantResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	resourceS2R, granteeS2R, err := parseGrantImportID(req.ID)
	if err != nil {
		resp.Diagnostics.AddError("Invalid import ID", err.Error())

		return
	}
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("resource_s2r"), resourceS2R)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("grantee_s2r"), granteeS2R)...)
}

// upsertGrant writes the grant via PutGrant (an upsert). retryAuthz
// retries PermissionDenied for ~30s on the create path to absorb the
// creator-grant write race. State is set by the caller from the plan:
// resource_s2r, grantee_s2r, and tier are all config-owned, so the
// server echo is intentionally not read back — writing a server-
// canonicalized value into a RequiresReplace attribute would trip the
// framework's post-apply consistency check.
func (r *grantResource) upsertGrant(ctx context.Context, plan grantModel, retryAuthz bool) diag.Diagnostics {
	var d diag.Diagnostics

	tier, err := tierFromString(plan.Tier.ValueString())
	if err != nil {
		d.AddError("Invalid tier", err.Error())

		return d
	}

	req := &orgsvcv1.PutGrantRequest{
		OrgS2R:      r.client.OrgS2R,
		ResourceS2R: plan.ResourceS2R.ValueString(),
		GranteeS2R:  plan.GranteeS2R.ValueString(),
		Tier:        tier,
	}

	if retryAuthz {
		err = r.putGrantRetryingAuthz(ctx, req)
		if err != nil {
			d.AddError("Creating grant", err.Error())
		}

		return d
	}

	_, err = r.client.OrgService.PutGrant(ctx, connect.NewRequest(req))
	if err != nil {
		d.AddError("Updating grant", err.Error())
	}

	return d
}

// putGrantRetryingAuthz is the Create-path PutGrant. It retries
// PermissionDenied for ~30s: a grant against a freshly
// proposal-created resource can race the server-side creator-grant
// write that authorizes this caller. Every other code fails
// immediately.
func (r *grantResource) putGrantRetryingAuthz(ctx context.Context, req *orgsvcv1.PutGrantRequest) error {
	waits := []time.Duration{
		1 * time.Second,
		2 * time.Second,
		4 * time.Second,
		8 * time.Second,
		8 * time.Second,
	}
	for attempt := 0; ; attempt++ {
		_, err := r.client.OrgService.PutGrant(ctx, connect.NewRequest(req))
		if err == nil {
			return nil
		}
		if connect.CodeOf(err) != connect.CodePermissionDenied {
			return fmt.Errorf("PutGrant: %w", err)
		}
		if attempt >= len(waits) {
			return fmt.Errorf(
				"PutGrant still permission-denied after %d attempts: creating a grant on %s requires the calling principal to hold the %q tier on that resource (an org admin can grant it): %w",
				attempt+1, req.GetResourceS2R(), "edit", err,
			)
		}

		t := time.NewTimer(waits[attempt])
		select {
		case <-ctx.Done():
			t.Stop()

			return ctx.Err()
		case <-t.C:
		}
	}
}

func populateGrantModel(m *grantModel, g *orgsvcv1.Grant) diag.Diagnostics {
	var d diag.Diagnostics
	if g == nil {
		d.AddError("Decoding grant", "response contains no grant")

		return d
	}
	tierStr, err := tierToString(g.GetTier())
	if err != nil {
		d.AddError("Decoding grant", err.Error())

		return d
	}

	// Refresh only tier. resource_s2r and grantee_s2r are config-owned
	// RequiresReplace keys preserved from prior state; echoing the server's
	// (possibly canonicalized) value back would trip the framework's post-
	// apply consistency check -- same rationale as upsertGrant.
	m.Tier = types.StringValue(tierStr)

	return nil
}

var (
	errUnknownTier            = errors.New("unknown tier")
	errUnmappableTier         = errors.New("unmappable tier enum value")
	errMalformedGrantImportID = errors.New("malformed grant import ID")
)

type tierMapping struct {
	name string
	tier authzv1.Tier
}

// tierMappings is the single source of truth for the Terraform-string
// <-> authz enum correspondence; the schema validator, both converters,
// and the docs string all derive from it.
func tierMappings() []tierMapping {
	return []tierMapping{
		{name: "view", tier: authzv1.Tier_TIER_VIEW},
		{name: "use", tier: authzv1.Tier_TIER_USE},
		{name: "edit", tier: authzv1.Tier_TIER_EDIT},
	}
}

func tierValues() []string {
	mappings := tierMappings()
	names := make([]string, 0, len(mappings))
	for _, m := range mappings {
		names = append(names, m.name)
	}

	return names
}

func tierFromString(s string) (authzv1.Tier, error) {
	for _, m := range tierMappings() {
		if m.name == s {
			return m.tier, nil
		}
	}

	return authzv1.Tier_TIER_UNSPECIFIED, fmt.Errorf("%w: %q (expected one of: %s)", errUnknownTier, s, strings.Join(tierValues(), ", "))
}

func tierToString(t authzv1.Tier) (string, error) {
	for _, m := range tierMappings() {
		if m.tier == t {
			return m.name, nil
		}
	}

	return "", fmt.Errorf("%w: %d (%s)", errUnmappableTier, t, t)
}

func parseGrantImportID(id string) (string, string, error) {
	resourceS2R, granteeS2R, found := strings.Cut(id, ",")
	if !found || resourceS2R == "" || granteeS2R == "" || strings.Contains(granteeS2R, ",") {
		return "", "", fmt.Errorf("%w: %q (expected \"<resource_s2r>,<grantee_s2r>\", exactly one comma)", errMalformedGrantImportID, id)
	}

	return resourceS2R, granteeS2R, nil
}
