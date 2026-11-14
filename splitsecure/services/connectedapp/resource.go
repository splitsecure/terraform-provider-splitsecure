// Package connectedapp implements the SplitSecure connected app Terraform resource.
package connectedapp

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/mapplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"
	"google.golang.org/protobuf/proto"

	pb "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/connectedapp/v1"
	vaultusev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
	catalog "github.com/splitsecure/terraform-provider-splitsecure/splitsecure/connectedapp"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultres"
)

var (
	_ resource.Resource                   = (*appResource)(nil)
	_ resource.ResourceWithImportState    = (*appResource)(nil)
	_ resource.ResourceWithValidateConfig = (*appResource)(nil)
	_ resource.ResourceWithModifyPlan     = (*appResource)(nil)
)

const kindConnectedApp = "connected-app"

var errUnexpectedKind = errors.New("record is not a connected app")

type appResource struct {
	client *client.Client
}

type appModel struct {
	ID                 types.String `tfsdk:"id"`
	VaultID            types.String `tfsdk:"vault_id"`
	IssuerVaultID      types.String `tfsdk:"issuer_vault_id"`
	IssuerID           types.String `tfsdk:"issuer_id"`
	Template           types.String `tfsdk:"template"`
	Title              types.String `tfsdk:"title"`
	DerivedValues      types.Map    `tfsdk:"derived_values"`
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	NotificationPolicy types.String `tfsdk:"notification_policy"`
	Sensitivity        types.String `tfsdk:"sensitivity"`
	Folder             types.List   `tfsdk:"folder"`
	FolderID           types.String `tfsdk:"folder_id"`
	Justification      types.String `tfsdk:"justification"`
	Wait               types.String `tfsdk:"wait"`
	SAML2              types.List   `tfsdk:"saml2"`
	OIDC               types.List   `tfsdk:"oidc"`
	Fields             types.List   `tfsdk:"field"`
	NameID             types.List   `tfsdk:"name_id"`
}

type saml2Model struct {
	EntityID    types.String `tfsdk:"entity_id"`
	ACSURL      types.String `tfsdk:"acs_url"`
	MetadataXML types.String `tfsdk:"metadata_xml"`
}

type affixModel struct {
	Prefix    types.String `tfsdk:"prefix"`
	Suffix    types.String `tfsdk:"suffix"`
	MaxLength types.Int64  `tfsdk:"max_length"`
}

type oidcModel struct {
	KeyID types.String `tfsdk:"key_id"`
}

type nameIDModel struct {
	Parts types.List `tfsdk:"parts"`
}

type fieldModel struct {
	Name          types.String `tfsdk:"name"`
	Key           types.String `tfsdk:"key"`
	Value         types.String `tfsdk:"value"`
	Values        types.List   `tfsdk:"values"`
	Seconds       types.Int64  `tfsdk:"seconds"`
	DurationRange types.List   `tfsdk:"duration_range"`
	Choices       types.List   `tfsdk:"choices"`
	DefaultValue  types.String `tfsdk:"default_value"`
	DefaultValues types.List   `tfsdk:"default_values"`
	Affix         types.List   `tfsdk:"affix"`
	Requester     types.String `tfsdk:"requester"`
	Suffix        types.String `tfsdk:"suffix"`
	Derived       types.String `tfsdk:"derived"`
	JSON          types.String `tfsdk:"json"`
}

type durationRangeModel struct {
	MinSeconds     types.Int64 `tfsdk:"min_seconds"`
	MaxSeconds     types.Int64 `tfsdk:"max_seconds"`
	DefaultSeconds types.Int64 `tfsdk:"default_seconds"`
}

func saml2Type() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{"entity_id": types.StringType, "acs_url": types.StringType, "metadata_xml": types.StringType}}
}

func affixType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{"prefix": types.StringType, "suffix": types.StringType, "max_length": types.Int64Type}}
}

func oidcType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{"key_id": types.StringType}}
}

func nameIDType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{"parts": types.ListType{ElemType: types.StringType}}}
}

func durationRangeType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"min_seconds": types.Int64Type, "max_seconds": types.Int64Type, "default_seconds": types.Int64Type,
	}}
}

func fieldType() types.ObjectType {
	stringList := types.ListType{ElemType: types.StringType}

	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"name": types.StringType, "key": types.StringType, "value": types.StringType, "values": stringList,
		"seconds": types.Int64Type, "duration_range": types.ListType{ElemType: durationRangeType()},
		"choices": stringList, "default_value": types.StringType, "default_values": stringList,
		"affix": types.ListType{ElemType: affixType()}, "requester": types.StringType, "suffix": types.StringType,
		"derived": types.StringType, "json": types.StringType,
	}}
}

// NewConnectedAppResource returns a factory for the connected app resource.
func NewConnectedAppResource() resource.Resource {
	return &appResource{}
}

func (r *appResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_connected_app"
}

func (r *appResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = vaultres.ClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *appResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := vaultres.CommonAttributes("connected app")

	attrs["vault_id"] = schema.StringAttribute{
		Computed:      true,
		Description:   "Vault the connected app lives in, the vault of its issuer.",
		PlanModifiers: vaultres.ComputedOnce(),
	}
	attrs["issuer_vault_id"] = schema.StringAttribute{
		Required:      true,
		Description:   "Vault of the issuer record. The app is created in it. Changing it replaces the resource.",
		PlanModifiers: vaultres.ForceNew(),
		Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
	}
	attrs["issuer_id"] = schema.StringAttribute{
		Required:      true,
		Description:   "Id of the SAML2 identity provider or OIDC issuer record that signs for the app. Changing it replaces the resource.",
		PlanModifiers: vaultres.ForceNew(),
		Validators:    []validator.String{stringvalidator.LengthAtLeast(1)},
	}
	attrs["template"] = schema.StringAttribute{
		Required:      true,
		Description:   "Catalog template the app is built from, such as saml2/aws or oidc/aws. Changing it replaces the resource.",
		PlanModifiers: vaultres.ForceNew(),
		Validators:    []validator.String{stringvalidator.OneOf(catalog.Names()...)},
	}
	attrs["title"] = schema.StringAttribute{
		Computed:      true,
		Description:   "Display name of the template.",
		PlanModifiers: vaultres.ComputedOnce(),
	}
	attrs["derived_values"] = schema.MapAttribute{
		ElementType: types.StringType,
		Computed:    true,
		Description: "Values the enclave derived when it created the app, by field name. For oidc/aws, subject is the sub claim the role's trust policy must match.",
		PlanModifiers: []planmodifier.Map{
			mapplanmodifier.UseStateForUnknown(),
		},
	}

	resp.Schema = schema.Schema{
		Description: "Connected app in a SplitSecure vault, built from a catalog template and bound to a SAML2 identity provider or an OIDC issuer. " +
			"Creating or deleting it may need approval, and the call waits for it. Changing the folder moves the record in place. " +
			"A change to the field, saml2, oidc or name_id blocks that builds the same app updates the state only. Changing any other input replaces the resource. " +
			"Import it as vault_id/id, or as vault_id/id/issuer_vault_id/issuer_id to skip the search for its issuer.",
		Attributes: attrs,
		Blocks: map[string]schema.Block{
			"saml2":   saml2Block(),
			"oidc":    oidcBlock(),
			"field":   fieldBlock(),
			"name_id": nameIDBlock(),
		},
	}
}

func atMostOne() []validator.List {
	return []validator.List{listvalidator.SizeAtMost(1)}
}

func saml2Block() schema.ListNestedBlock {
	return schema.ListNestedBlock{
		Description: "Service provider of a SAML2 template: entity_id and acs_url, or its metadata_xml. Set this block or oidc, not both. Changing it replaces the resource.",
		Validators:  atMostOne(),
		NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
			"entity_id": schema.StringAttribute{Optional: true, Description: "Entity id of the service provider, the assertion audience. Set it with acs_url."},
			"acs_url":   schema.StringAttribute{Optional: true, Description: "Assertion consumer service URL, posted to with HTTP-POST. Set it with entity_id."},
			"metadata_xml": schema.StringAttribute{
				Optional: true,
				Description: "SAML 2.0 metadata of the service provider: one EntityDescriptor. Set it in place of entity_id and acs_url. " +
					"A formatting change that keeps the same metadata updates the state only.",
			},
		}},
	}
}

func oidcBlock() schema.ListNestedBlock {
	return schema.ListNestedBlock{
		Description: "Signing key of an OIDC template. Set this block or saml2, not both. Changing it replaces the resource.",
		Validators:  atMostOne(),
		NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
			"key_id": schema.StringAttribute{Required: true, Description: "Base64 vault key id of the issuer key that signs tokens, as the issuer's keys export it."},
		}},
	}
}

func nameIDBlock() schema.ListNestedBlock {
	return schema.ListNestedBlock{
		Description: "NameID of a SAML2 app, built from parts. Replaces the template's name_id field wherever the layout places it. Changing it replaces the resource.",
		Validators:  atMostOne(),
		NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
			"parts": schema.ListAttribute{
				ElementType: types.StringType,
				Required:    true,
				Validators:  []validator.List{listvalidator.SizeAtLeast(1)},
				Description: "Parts joined in order. A part starting with field: is the value of the named field; any other part is literal text.",
			},
		}},
	}
}

func fieldBlock() schema.ListNestedBlock {
	sourced := "Set exactly one of value, values, seconds, duration_range, choices or affix with its default, requester, derived and json."

	return schema.ListNestedBlock{
		Description: "One field of the template. " + sourced + " Reordering the field blocks plans an in-place update that changes nothing on the server. Any other change to a field replaces the resource.",
		NestedObject: schema.NestedBlockObject{
			Attributes: map[string]schema.Attribute{
				"name": schema.StringAttribute{Required: true, Description: "Field name as the template declares it, such as role_arn."},
				"key": schema.StringAttribute{
					Optional:    true,
					Description: "Marks the entry as an instance of a repeatable field, carried under this key: a session tag key, a claim name or an attribute name.",
				},
				"value":   schema.StringAttribute{Optional: true, Description: "Fixed text."},
				"values":  schema.ListAttribute{ElementType: types.StringType, Optional: true, Description: "Fixed list of text."},
				"seconds": schema.Int64Attribute{Optional: true, Description: "Fixed duration in seconds."},
				"choices": schema.ListAttribute{
					ElementType: types.StringType,
					Optional:    true,
					Description: "Values each sign-in chooses from: one for a text field, any of them for a list field. Defaults to the template's choices for the field.",
				},
				"default_value": schema.StringAttribute{Optional: true, Description: "Value a sign-in gets when it sets none, for a text field with choices or affix."},
				"default_values": schema.ListAttribute{
					ElementType: types.StringType,
					Optional:    true,
					Description: "Choices a sign-in gets when it chooses none, for a list field.",
				},
				"requester": schema.StringAttribute{
					Optional:    true,
					Description: "Text filled from the requester: email or session_name.",
					Validators:  []validator.String{stringvalidator.OneOf(requesterEmail, requesterSessionName)},
				},
				"suffix": schema.StringAttribute{Optional: true, Description: "Ending a requester value must have, such as @corp.example."},
				"derived": schema.StringAttribute{
					Optional:    true,
					Description: "Text the enclave derives: at_creation or per_sign_in.",
					Validators:  []validator.String{stringvalidator.OneOf(derivedAtCreation, derivedPerSignIn)},
				},
				"json": schema.StringAttribute{Optional: true, Description: "Fixed JSON object, such as jsonencode({team = \"platform\"}). Numbers must be integers."},
			},
			Blocks: map[string]schema.Block{
				"affix": schema.ListNestedBlock{
					Description: "Text each sign-in sets within a prefix, a suffix and a length, for a text field. Set it in place of choices.",
					Validators:  atMostOne(),
					NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
						"prefix":     schema.StringAttribute{Optional: true, Description: "Beginning the value must have."},
						"suffix":     schema.StringAttribute{Optional: true, Description: "Ending the value must have."},
						"max_length": schema.Int64Attribute{Optional: true, Description: "Most bytes the value may have. Unset or 0 sets no limit."},
					}},
				},
				"duration_range": schema.ListNestedBlock{
					Description: "Duration each sign-in chooses within bounds, in seconds.",
					Validators:  atMostOne(),
					NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
						"min_seconds":     schema.Int64Attribute{Required: true, Description: "Shortest duration a sign-in may choose."},
						"max_seconds":     schema.Int64Attribute{Required: true, Description: "Longest duration a sign-in may choose."},
						"default_seconds": schema.Int64Attribute{Optional: true, Description: "Duration a sign-in gets when it chooses none."},
					}},
				},
			},
		},
	}
}

// ValidateConfig builds the create params at plan time, so template errors surface before apply. A field block whose
// values are not known yet counts as set and skips its own checks.
func (r *appResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	if !shapeKnown(req.Config.Raw) {
		return
	}

	var m appModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &m)...)

	if resp.Diagnostics.HasError() {
		return
	}

	_, diags := params(ctx, &m)
	resp.Diagnostics.Append(diags...)
}

// buildInputsKnown reports whether every input params reads is known, so an unknown issuer id does not delay the check.
func buildInputsKnown(raw tftypes.Value) bool {
	var attrs map[string]tftypes.Value

	err := raw.As(&attrs)
	if err != nil || attrs == nil {
		return false
	}

	for _, name := range []string{"template", "saml2", "oidc", "field", "name_id"} {
		if !attrs[name].IsFullyKnown() {
			return false
		}
	}

	return true
}

// shapeKnown reports whether the build checks can run: the template, the NameID, how many blocks there are, and the
// name and key of each field block are known.
func shapeKnown(raw tftypes.Value) bool {
	var attrs map[string]tftypes.Value

	err := raw.As(&attrs)
	if err != nil || attrs == nil || !attrs["template"].IsKnown() || !attrs["name_id"].IsFullyKnown() || !attrs["saml2"].IsKnown() || !attrs["oidc"].IsKnown() {
		return false
	}

	var fields []tftypes.Value

	err = attrs["field"].As(&fields)

	return err == nil && !slices.ContainsFunc(fields, func(f tftypes.Value) bool {
		var fa map[string]tftypes.Value

		return f.As(&fa) != nil || !fa["name"].IsKnown() || !fa["key"].IsKnown()
	})
}

func (r *appResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan appModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	opts := vaultres.WriteOptionsFromConfig(ctx, req.Config, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	app, diags := params(ctx, &plan)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	vaultID := plan.IssuerVaultID.ValueString()

	parentID, ok := vaultres.ParentNode(ctx, r.client.VaultBrowse, vaultID, plan.Folder, plan.FolderID, &resp.Diagnostics)
	if !ok {
		return
	}

	created, err := r.client.VaultUse.CreateConnectedApp(ctx, connect.NewRequest(&vaultusev1.CreateConnectedAppRequest{
		Base: &vaultusev1.CreateConnectedAppRequest_Base{
			VaultId:  vaultID,
			IssuerId: plan.IssuerID.ValueString(),
			Common: vaultapi.CreateCommon(vaultapi.CreateCommonInput{
				Name:               plan.Name.ValueString(),
				Description:        plan.Description.ValueString(),
				NotificationPolicy: plan.NotificationPolicy.ValueString(),
				Sensitivity:        plan.Sensitivity.ValueString(),
				ParentNodeID:       parentID,
			}),
			App:     app,
			Options: opts,
		},
	}))
	if err != nil {
		resp.Diagnostics.AddError("Creating connected app", err.Error())

		return
	}

	result, err := vaultapi.AwaitCreate(ctx, r.client.VaultUse, vaultID, created.Msg.GetOutcome())
	if err != nil {
		keepCreatedID(ctx, resp, result, vaultID)
		resp.Diagnostics.AddError("Creating connected app", err.Error())

		return
	}

	plan.ID = types.StringValue(result.GetSecretId())
	plan.VaultID = types.StringValue(vaultID)

	rec, err := vaultapi.FetchRecord(ctx, r.client.VaultBrowse, vaultID, plan.ID.ValueString())
	if err == nil {
		_, err = populate(&plan, rec)
	}

	if err != nil {
		keepCreatedID(ctx, resp, result, vaultID)
		resp.Diagnostics.AddError("Reading new connected app", err.Error())

		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

// keepCreatedID records the id of an app that exists, so Terraform taints it rather than orphaning it. A nil result records nothing.
func keepCreatedID(ctx context.Context, resp *resource.CreateResponse, result *vaultusev1.CreateResult, vaultID string) {
	if result == nil {
		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), result.GetSecretId())...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vault_id"), vaultID)...)
}

func (r *appResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state appModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	rec, err := vaultapi.FetchRecord(ctx, r.client.VaultBrowse, state.VaultID.ValueString(), state.ID.ValueString())
	if vaultapi.IsNotFound(err) {
		resp.State.RemoveResource(ctx)

		return
	}

	if err != nil {
		resp.Diagnostics.AddError("Reading connected app", err.Error())

		return
	}

	app, err := populate(&state, rec)
	if err != nil {
		resp.Diagnostics.AddError("Reading connected app", err.Error())

		return
	}

	if hasInputs(&state) {
		err = inputsBuildRecord(ctx, &state, app)
		if err != nil {
			resp.Diagnostics.AddWarning("Connected app differs from its configuration",
				err.Error()+". Terraform keeps the configured blocks. Replace the resource to rebuild the app from them.")
		}
	} else if !r.readImported(ctx, &state, app, &resp.Diagnostics) {
		return
	}

	state.Folder, state.FolderID, err = vaultres.ObservePlacement(ctx, r.client.VaultBrowse, state.VaultID.ValueString(), state.ID.ValueString(), state.Folder, state.FolderID)
	if errors.Is(err, vaultres.ErrRecordGone) {
		resp.State.RemoveResource(ctx)

		return
	}

	if err != nil {
		resp.Diagnostics.AddError("Reading folder placement", err.Error())

		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *appResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state appModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	changed, err := changedBlocks(req.Plan.Raw, req.State.Raw)
	if err != nil {
		resp.Diagnostics.AddError("Comparing plan and state", err.Error())

		return
	}

	if len(changed) > 0 && !sameApp(ctx, &plan, &state) {
		resp.Diagnostics.AddError("Update not supported", errInputsDiffer.Error()+".")

		return
	}

	state.SAML2, state.OIDC, state.Fields, state.NameID = plan.SAML2, plan.OIDC, plan.Fields, plan.NameID

	// The input blocks build the same app, so MoveRecord compares the plan against a state that holds them.
	move := req
	resp.Diagnostics.Append(move.State.Set(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if !move.State.Raw.Equal(req.Plan.Raw) && !vaultres.MoveRecord(ctx, move, r.client.VaultBrowse, vaultres.Placement{
		VaultID: state.VaultID.ValueString(), NodeID: state.ID.ValueString(), Folder: plan.Folder, FolderID: plan.FolderID,
	}, &resp.Diagnostics) {
		return
	}

	state.Folder = plan.Folder
	state.FolderID = plan.FolderID

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *appResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state appModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	vaultID := state.VaultID.ValueString()

	deleted, err := r.client.VaultUse.Delete(ctx, connect.NewRequest(&vaultusev1.DeleteRequest{
		Base: &vaultusev1.DeleteRequest_Base{
			VaultId:  vaultID,
			SecretId: state.ID.ValueString(),
			Options:  vaultres.DestroyOptions("connected app", state.Name.ValueString()),
		},
	}))
	if vaultapi.IsNotFound(err) {
		return
	}

	if err != nil {
		resp.Diagnostics.AddError("Deleting connected app", err.Error())

		return
	}

	err = vaultapi.AwaitDelete(ctx, r.client.VaultUse, vaultID, deleted.Msg.GetOutcome())
	if err != nil {
		resp.Diagnostics.AddError("Deleting connected app", err.Error())
	}
}

// ImportState takes vault_id/id, or vault_id/id/issuer_vault_id/issuer_id to name the issuer instead of searching the vault for it.
func (r *appResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	parts := strings.Split(req.ID, "/")
	if (len(parts) != 2 && len(parts) != 4) || slices.Contains(parts, "") {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("expected vault_id/id or vault_id/id/issuer_vault_id/issuer_id, got %q", req.ID))

		return
	}

	names := []string{"vault_id", "id", "issuer_vault_id", "issuer_id"}
	for i, p := range parts {
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root(names[i]), p)...)
	}
}

// readImported sets the input blocks of an imported app from its record, and its issuer: searched for, or checked when the import id names it.
func (r *appResource) readImported(ctx context.Context, state *appModel, app *pb.ConnectedAppParams, diags *diag.Diagnostics) bool {
	err := importInputs(ctx, state, app)
	if err != nil {
		diags.AddError("Reading connected app", err.Error())

		return false
	}

	if !state.IssuerID.IsNull() {
		err := checkIssuer(ctx, r.client.VaultBrowse, state.IssuerVaultID.ValueString(), state.IssuerID.ValueString(), app)
		if err != nil {
			diags.AddError("Checking the issuer of the connected app", err.Error())
		}

		return err == nil
	}

	issuerID, err := findIssuer(ctx, r.client.VaultBrowse, state.VaultID.ValueString(), app)
	if err != nil {
		diags.AddError("Finding the issuer of the connected app", err.Error())

		return false
	}

	state.IssuerID = types.StringValue(issuerID)

	return true
}

// populate fills the computed and common attributes from a fetched record and returns the app it holds.
func populate(m *appModel, rec *vaultapi.Record) (*pb.ConnectedAppParams, error) {
	if rec.Kind != kindConnectedApp {
		return nil, fmt.Errorf("%w: kind %q", errUnexpectedKind, rec.Kind)
	}

	var app pb.ConnectedAppParams

	err := proto.Unmarshal(rec.Params, &app)
	if err != nil {
		return nil, fmt.Errorf("decoding connected app params: %w", err)
	}

	attrs := rec.Attributes
	m.Name = types.StringValue(attrs.GetName())
	m.Description = types.StringValue(attrs.GetDescription())
	m.NotificationPolicy = types.StringValue(vaultapi.NotificationPolicyToString(attrs.GetNotificationPolicy()))
	m.Sensitivity = vaultres.SensitivityState(vaultapi.SensitivityToString(attrs.GetSensitivity()))

	// A template that differs from the record's plans a replacement.
	m.Template = types.StringValue(app.GetTemplate())
	m.Title = types.StringValue(app.GetTitle())
	m.DerivedValues = derivedValues(&app)

	if m.IssuerVaultID.IsNull() {
		m.IssuerVaultID = m.VaultID
	}

	return &app, nil
}

// derivedValues maps each text field the enclave derived at creation to its value.
func derivedValues(app *pb.ConnectedAppParams) types.Map {
	values := map[string]attr.Value{}

	for _, f := range app.GetFields() {
		if derived := f.GetStringField().GetDerivedText(); derived != nil {
			values[f.GetName()] = types.StringValue(derived.GetValue())
		}
	}

	return types.MapValueMust(types.StringType, values)
}
