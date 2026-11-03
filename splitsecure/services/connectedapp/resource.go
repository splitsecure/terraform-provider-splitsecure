// Package connectedapp implements the SplitSecure connected app Terraform resource.
package connectedapp

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
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
)

// kindConnectedApp is the record kind of a connected app.
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
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	NotificationPolicy types.String `tfsdk:"notification_policy"`
	Sensitivity        types.String `tfsdk:"sensitivity"`
	Folder             types.List   `tfsdk:"folder"`
	Justification      types.String `tfsdk:"justification"`
	Wait               types.String `tfsdk:"wait"`
	SAML2              types.List   `tfsdk:"saml2"`
	OIDC               types.List   `tfsdk:"oidc"`
	Fields             types.List   `tfsdk:"field"`
	NameID             types.List   `tfsdk:"name_id"`
}

type saml2Model struct {
	EntityID types.String `tfsdk:"entity_id"`
	ACSURL   types.String `tfsdk:"acs_url"`
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
	return types.ObjectType{AttrTypes: map[string]attr.Type{"entity_id": types.StringType, "acs_url": types.StringType}}
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
		"choices": stringList, "default_value": types.StringType, "requester": types.StringType, "suffix": types.StringType,
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

	resp.Schema = schema.Schema{
		Description: "Connected app in a SplitSecure vault, built from a catalog template and bound to a SAML2 identity provider or an OIDC issuer. " +
			"Creating or deleting it may need approval, and the call waits for it. There is no in-place update: changing any input replaces the resource.",
		Attributes: attrs,
		Blocks: map[string]schema.Block{
			"saml2":   saml2Block(),
			"oidc":    oidcBlock(),
			"field":   fieldBlock(),
			"name_id": nameIDBlock(),
		},
	}
}

func replaceList() []planmodifier.List {
	return []planmodifier.List{listplanmodifier.RequiresReplace()}
}

func atMostOne() []validator.List {
	return []validator.List{listvalidator.SizeAtMost(1)}
}

func saml2Block() schema.ListNestedBlock {
	return schema.ListNestedBlock{
		Description:   "Service provider of a SAML2 template. Set this block or oidc, not both. Changing it replaces the resource.",
		PlanModifiers: replaceList(),
		Validators:    atMostOne(),
		NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
			"entity_id": schema.StringAttribute{Required: true, Description: "Entity id of the service provider, the assertion audience."},
			"acs_url":   schema.StringAttribute{Required: true, Description: "Assertion consumer service URL, posted to with HTTP-POST."},
		}},
	}
}

func oidcBlock() schema.ListNestedBlock {
	return schema.ListNestedBlock{
		Description:   "Signing key of an OIDC template. Set this block or saml2, not both. Changing it replaces the resource.",
		PlanModifiers: replaceList(),
		Validators:    atMostOne(),
		NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
			"key_id": schema.StringAttribute{Required: true, Description: "Base64 vault key id of the issuer key that signs tokens, as the issuer's keys export it."},
		}},
	}
}

func nameIDBlock() schema.ListNestedBlock {
	return schema.ListNestedBlock{
		Description:   "NameID of a SAML2 app, built from parts. Replaces the template's name_id field wherever the layout places it. Changing it replaces the resource.",
		PlanModifiers: replaceList(),
		Validators:    atMostOne(),
		NestedObject: schema.NestedBlockObject{Attributes: map[string]schema.Attribute{
			"parts": schema.ListAttribute{
				ElementType: types.StringType,
				Required:    true,
				Description: "Parts joined in order. A part starting with field: is the value of the named field; any other part is literal text.",
			},
		}},
	}
}

func fieldBlock() schema.ListNestedBlock {
	sourced := "Set exactly one of value, values, seconds, duration_range, choices or default_value, requester, derived and json."

	return schema.ListNestedBlock{
		Description:   "One field of the template. " + sourced + " Changing any field replaces the resource.",
		PlanModifiers: replaceList(),
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
					Description: "Text each sign-in chooses from. Defaults to the template's choices for the field.",
				},
				"default_value": schema.StringAttribute{Optional: true, Description: "Choice a sign-in gets when it chooses none."},
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

// ValidateConfig builds the create params at plan time once the whole config is known, so template errors surface before apply.
func (r *appResource) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	if !buildInputsKnown(req.Config.Raw) {
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

	parentID, ok := vaultres.EnsureFolder(ctx, r.client.VaultBrowse, vaultID, plan.Folder, &resp.Diagnostics)
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
		resp.Diagnostics.AddError("Creating connected app", err.Error())

		return
	}

	plan.ID = types.StringValue(result.GetSecretId())
	plan.VaultID = types.StringValue(vaultID)

	rec, err := vaultapi.FetchRecord(ctx, r.client.VaultBrowse, vaultID, plan.ID.ValueString())
	if err == nil {
		err = populate(ctx, &plan, rec)
	}

	if err != nil {
		// Record the id so the created app is tainted rather than orphaned.
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vault_id"), plan.VaultID)...)
		resp.Diagnostics.AddError("Reading new connected app", err.Error())

		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
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

	err = populate(ctx, &state, rec)
	if err != nil {
		resp.Diagnostics.AddError("Reading connected app", err.Error())

		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is unreachable because every input forces replacement.
func (r *appResource) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"Update not supported",
		"splitsecure_connected_app has no in-place update; every input forces replacement.",
	)
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

func (r *appResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	vaultID, id, ok := vaultres.SplitImportID(req.ID)
	if !ok {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("expected vault_id/id, got %q", req.ID))

		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vault_id"), vaultID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

// populate fills the model from a fetched record. The record does not hold the issuer id or the fields as configured, so
// those keep their state value; the binding block and issuer vault are read back only when state lacks them, as after import.
func populate(ctx context.Context, m *appModel, rec *vaultapi.Record) error {
	if rec.Kind != kindConnectedApp {
		return fmt.Errorf("%w: kind %q", errUnexpectedKind, rec.Kind)
	}

	var app pb.ConnectedAppParams

	err := proto.Unmarshal(rec.Params, &app)
	if err != nil {
		return fmt.Errorf("decoding connected app params: %w", err)
	}

	attrs := rec.Attributes
	m.Name = types.StringValue(attrs.GetName())
	m.Description = types.StringValue(attrs.GetDescription())
	m.NotificationPolicy = types.StringValue(vaultapi.NotificationPolicyToString(attrs.GetNotificationPolicy()))
	m.Sensitivity = types.StringValue(vaultapi.SensitivityToString(attrs.GetSensitivity()))

	// A template that differs from the record's plans a replacement.
	m.Template = types.StringValue(app.GetTemplate())
	m.Title = types.StringValue(app.GetTitle())

	if m.IssuerVaultID.IsNull() {
		m.IssuerVaultID = m.VaultID
	}

	var diags diag.Diagnostics

	if m.SAML2.IsNull() && m.OIDC.IsNull() {
		m.SAML2, m.OIDC = bindingBlocks(ctx, &app, &diags)
	}

	m.Fields = emptyIfNull(m.Fields, fieldType())
	m.NameID = emptyIfNull(m.NameID, nameIDType())

	if diags.HasError() {
		return fmt.Errorf("building binding blocks: %s", diags.Errors()[0].Detail()) //nolint:err113 // diagnostics carry no wrappable error.
	}

	return nil
}

// bindingBlocks returns the saml2 and oidc blocks the record's binding holds.
func bindingBlocks(ctx context.Context, app *pb.ConnectedAppParams, diags *diag.Diagnostics) (types.List, types.List) {
	var (
		saml2 = []saml2Model{}
		oidc  = []oidcModel{}
	)

	if b := app.GetSaml2().GetBinding(); b != nil {
		desc := b.GetSpMetadata().GetEntityDescriptor()
		acs := ""

		for _, sp := range desc.GetSpSsoDescriptor() {
			for _, ep := range sp.GetAssertionConsumerService() {
				if acs == "" || ep.GetIsDefault() {
					acs = ep.GetBase().GetLocation()
				}
			}
		}

		saml2 = append(saml2, saml2Model{EntityID: types.StringValue(desc.GetEntityId()), ACSURL: types.StringValue(acs)})
	}

	if b := app.GetOidc().GetBinding(); b != nil {
		oidc = append(oidc, oidcModel{KeyID: types.StringValue(base64.StdEncoding.EncodeToString(b.GetKeyId()))})
	}

	saml2List, d := types.ListValueFrom(ctx, saml2Type(), saml2)
	diags.Append(d...)

	oidcList, d := types.ListValueFrom(ctx, oidcType(), oidc)
	diags.Append(d...)

	return saml2List, oidcList
}

func emptyIfNull(l types.List, elem attr.Type) types.List {
	if !l.IsNull() {
		return l
	}

	return types.ListValueMust(elem, []attr.Value{})
}
