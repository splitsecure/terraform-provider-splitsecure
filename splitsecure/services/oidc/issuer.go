// Package oidc implements the SplitSecure OIDC issuer Terraform resource.
package oidc

import (
	"bytes"
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/attr"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/booldefault"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/boolplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/listplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	wifv2 "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveservices/wif/v2"
	keysv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/keys/v1"
	vaultusev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultres"
)

var (
	_ resource.Resource                = (*issuerResource)(nil)
	_ resource.ResourceWithImportState = (*issuerResource)(nil)
)

var errUnexpectedKind = errors.New("record is not an OIDC issuer")

type issuerResource struct {
	client *client.Client
}

type issuerModel struct {
	ID                 types.String `tfsdk:"id"`
	VaultID            types.String `tfsdk:"vault_id"`
	Name               types.String `tfsdk:"name"`
	Description        types.String `tfsdk:"description"`
	NotificationPolicy types.String `tfsdk:"notification_policy"`
	Sensitivity        types.String `tfsdk:"sensitivity"`
	Folder             types.List   `tfsdk:"folder"`
	FolderID           types.String `tfsdk:"folder_id"`
	Justification      types.String `tfsdk:"justification"`
	Wait               types.String `tfsdk:"wait"`
	Algs               types.List   `tfsdk:"algs"`
	AllowFreeForm      types.Bool   `tfsdk:"allow_free_form_tokens"`
	Issuer             types.String `tfsdk:"issuer"`
	JWKSURL            types.String `tfsdk:"jwks_url"`
	AuthorityID        types.String `tfsdk:"authority_id"`
	Keys               types.List   `tfsdk:"keys"`
	NotBefore          types.String `tfsdk:"not_before"`
	NotAfter           types.String `tfsdk:"not_after"`
}

type issuerKeyModel struct {
	Kid   types.String `tfsdk:"kid"`
	Alg   types.String `tfsdk:"alg"`
	KeyID types.String `tfsdk:"key_id"`
}

func issuerKeyType() types.ObjectType {
	return types.ObjectType{AttrTypes: map[string]attr.Type{
		"kid":    types.StringType,
		"alg":    types.StringType,
		"key_id": types.StringType,
	}}
}

// NewIssuerResource returns a factory for the OIDC issuer resource.
func NewIssuerResource() resource.Resource {
	return &issuerResource{}
}

func (r *issuerResource) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_oidc_issuer"
}

func (r *issuerResource) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = vaultres.ClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *issuerResource) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := vaultres.CommonAttributes("OIDC issuer")

	attrs["algs"] = schema.ListAttribute{
		ElementType: types.StringType,
		Optional:    true,
		Description: "Signing algorithms the issuer publishes keys for. Leave unset for the default key set. Changing it replaces the resource.",
		PlanModifiers: []planmodifier.List{
			listplanmodifier.RequiresReplace(),
		},
		Validators: []validator.List{
			listvalidator.UniqueValues(),
			listvalidator.ValueStringsAre(stringvalidator.OneOf(vaultapi.AlgValues()...)),
		},
	}
	attrs["allow_free_form_tokens"] = schema.BoolAttribute{
		Optional:      true,
		Computed:      true,
		Default:       booldefault.StaticBool(false),
		Description:   "Whether the issuer may mint tokens with caller-chosen claims. Changing it replaces the resource.",
		PlanModifiers: []planmodifier.Bool{boolplanmodifier.RequiresReplace()},
	}

	for name, description := range map[string]string{
		"issuer":       "Issuer URL, the iss claim of minted tokens.",
		"jwks_url":     "URL of the JSON Web Key Set that verifies minted tokens.",
		"authority_id": "Id of the issuing authority.",
		"not_before":   "Start of the issuer validity, as an RFC 3339 timestamp.",
		"not_after":    "End of the issuer validity, as an RFC 3339 timestamp.",
	} {
		attrs[name] = schema.StringAttribute{
			Computed:      true,
			Description:   description,
			PlanModifiers: vaultres.ComputedOnce(),
		}
	}

	attrs["keys"] = schema.ListNestedAttribute{
		Computed:      true,
		Description:   "Signing keys bound to the issuer, one per algorithm. A connected app names one by key_id.",
		PlanModifiers: []planmodifier.List{listplanmodifier.UseStateForUnknown()},
		NestedObject: schema.NestedAttributeObject{
			Attributes: map[string]schema.Attribute{
				"kid":    schema.StringAttribute{Computed: true, Description: "Key id in the JWKS, the JWK thumbprint. Null when the issuer publishes no key for the binding."},
				"alg":    schema.StringAttribute{Computed: true, Description: "Signing algorithm of the key."},
				"key_id": schema.StringAttribute{Computed: true, Description: "Base64-encoded vault key id."},
			},
		},
	}

	resp.Schema = schema.Schema{
		Description: "OIDC issuer in a SplitSecure vault, backed by a workload identity authority. Creating or deleting it may need approval, and the call waits for it. " +
			"Changing the folder moves the record in place. Changing any other input replaces the resource.",
		Attributes: attrs,
	}
}

func (r *issuerResource) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan issuerModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	opts := vaultres.WriteOptionsFromConfig(ctx, req.Config, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	algs, ok := signatureSpecs(ctx, plan.Algs, &resp.Diagnostics)
	if !ok {
		return
	}

	vaultID := plan.VaultID.ValueString()

	parentID, ok := vaultres.ParentNode(ctx, r.client.VaultBrowse, vaultID, plan.Folder, plan.FolderID, &resp.Diagnostics)
	if !ok {
		return
	}

	created, err := r.client.VaultUse.CreateWIFAuthority(ctx, connect.NewRequest(&vaultusev1.CreateWIFAuthorityRequest{
		Base: &vaultusev1.CreateWIFAuthorityRequest_Base{
			VaultId: vaultID,
			Common: vaultapi.CreateCommon(vaultapi.CreateCommonInput{
				Name:               plan.Name.ValueString(),
				Description:        plan.Description.ValueString(),
				NotificationPolicy: plan.NotificationPolicy.ValueString(),
				Sensitivity:        plan.Sensitivity.ValueString(),
				ParentNodeID:       parentID,
			}),
			Algs:                algs,
			Options:             opts,
			AllowFreeFormTokens: plan.AllowFreeForm.ValueBool(),
		},
	}))
	if err != nil {
		resp.Diagnostics.AddError("Creating OIDC issuer", err.Error())

		return
	}

	result, err := vaultapi.AwaitCreate(ctx, r.client.VaultUse, vaultID, created.Msg.GetOutcome())
	if err != nil {
		resp.Diagnostics.AddError("Creating OIDC issuer", err.Error())

		return
	}

	plan.ID = types.StringValue(result.GetSecretId())

	rec, err := vaultapi.FetchRecord(ctx, r.client.VaultBrowse, vaultID, plan.ID.ValueString())
	if err == nil {
		err = populate(ctx, &plan, rec)
	}

	if err != nil {
		// Record the id so the created issuer is tainted rather than orphaned.
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), plan.ID)...)
		resp.Diagnostics.AddError("Reading new OIDC issuer", err.Error())

		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *issuerResource) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state issuerModel

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
		resp.Diagnostics.AddError("Reading OIDC issuer", err.Error())

		return
	}

	err = populate(ctx, &state, rec)
	if err != nil {
		resp.Diagnostics.AddError("Reading OIDC issuer", err.Error())

		return
	}

	state.Folder, state.FolderID, err = vaultres.ObservePlacement(ctx, r.client.VaultBrowse, state.VaultID.ValueString(), state.ID.ValueString(), state.Folder, state.FolderID)
	if err != nil {
		resp.Diagnostics.AddError("Reading folder placement", err.Error())

		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *issuerResource) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state issuerModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	if !vaultres.MoveRecord(ctx, req, r.client.VaultBrowse, vaultres.Placement{
		VaultID: state.VaultID.ValueString(), NodeID: state.ID.ValueString(), Folder: plan.Folder, FolderID: plan.FolderID,
	}, &resp.Diagnostics) {
		return
	}

	state.Folder = plan.Folder
	state.FolderID = plan.FolderID

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *issuerResource) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state issuerModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	vaultID := state.VaultID.ValueString()

	deleted, err := r.client.VaultUse.Delete(ctx, connect.NewRequest(&vaultusev1.DeleteRequest{
		Base: &vaultusev1.DeleteRequest_Base{
			VaultId:  vaultID,
			SecretId: state.ID.ValueString(),
			Options:  vaultres.DestroyOptions("OIDC issuer", state.Name.ValueString()),
		},
	}))
	if vaultapi.IsNotFound(err) {
		return
	}

	if err != nil {
		resp.Diagnostics.AddError("Deleting OIDC issuer", err.Error())

		return
	}

	err = vaultapi.AwaitDelete(ctx, r.client.VaultUse, vaultID, deleted.Msg.GetOutcome())
	if err != nil {
		resp.Diagnostics.AddError("Deleting OIDC issuer", err.Error())
	}
}

func (r *issuerResource) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	vaultID, id, ok := vaultres.SplitImportID(req.ID)
	if !ok {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("expected vault_id/id, got %q", req.ID))

		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vault_id"), vaultID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

// populate fills the model from a fetched record. algs and allow_free_form_tokens are inputs the record does not echo, so they keep their state value.
func populate(ctx context.Context, m *issuerModel, rec *vaultapi.Record) error {
	if rec.Kind != vaultapi.KindWIFAuthority {
		return fmt.Errorf("%w: kind %q", errUnexpectedKind, rec.Kind)
	}

	authority, err := vaultapi.DecodeOIDCIssuer(rec.Params)
	if err != nil {
		return err
	}

	attrs := rec.Attributes
	m.Name = types.StringValue(attrs.GetName())
	m.Description = types.StringValue(attrs.GetDescription())
	m.NotificationPolicy = types.StringValue(vaultapi.NotificationPolicyToString(attrs.GetNotificationPolicy()))
	m.Sensitivity = types.StringValue(vaultapi.SensitivityToString(attrs.GetSensitivity()))

	m.Issuer = types.StringValue(authority.GetIssuer())
	m.JWKSURL = types.StringValue(authority.GetJwksUri())
	m.AuthorityID = types.StringValue(authority.GetAuthorityId())
	m.NotBefore = formatTimestamp(authority.GetNotBefore())
	m.NotAfter = formatTimestamp(authority.GetNotAfter())

	keys, diags := types.ListValueFrom(ctx, issuerKeyType(), keyModels(authority, rec))
	if diags.HasError() {
		return fmt.Errorf("building keys: %s", diags.Errors()[0].Detail()) //nolint:err113 // diagnostics carry no wrappable error.
	}

	m.Keys = keys

	return nil
}

func formatTimestamp(ts *timestamppb.Timestamp) types.String {
	if ts == nil {
		return types.StringNull()
	}

	return types.StringValue(ts.AsTime().UTC().Format(time.RFC3339))
}

// keyModels returns one key per signing key bound to the record, the key ids a connected app may name. A bound key is named
// by its JWS alg and carries the public key its published key holds, so the published key matches on those bytes.
func keyModels(authority *wifv2.WorkloadIdentityAuthorityState, rec *vaultapi.Record) []issuerKeyModel {
	keys := make([]issuerKeyModel, 0, len(rec.Materials))

	for _, material := range rec.Materials {
		published := publishedKeyFor(authority, material.GetForm().GetPrivateKey().GetPublicKey())

		alg := material.GetName()
		if alg == "" {
			alg = vaultapi.AlgFromSignatureSpec(published.GetPublicKey().GetSpec().GetSignature())
		}

		kid := types.StringNull()
		if published != nil {
			kid = types.StringValue(published.GetKid())
		}

		keys = append(keys, issuerKeyModel{
			Kid:   kid,
			Alg:   types.StringValue(alg),
			KeyID: types.StringValue(base64.StdEncoding.EncodeToString(material.GetKeyId())),
		})
	}

	return keys
}

// publishedKeyFor returns the published key holding publicKey, or nil.
func publishedKeyFor(authority *wifv2.WorkloadIdentityAuthorityState, publicKey []byte) *wifv2.PublishedKey {
	if len(publicKey) == 0 {
		return nil
	}

	for _, k := range authority.GetKeys() {
		if bytes.Equal(k.GetPublicKey().GetData(), publicKey) {
			return k
		}
	}

	return nil
}

func signatureSpecs(ctx context.Context, algs types.List, diags *diag.Diagnostics) ([]*keysv1.SignatureSpec, bool) {
	var names []string

	diags.Append(algs.ElementsAs(ctx, &names, false)...)

	if diags.HasError() {
		return nil, false
	}

	specs := make([]*keysv1.SignatureSpec, 0, len(names))

	for _, name := range names {
		spec, err := vaultapi.SignatureSpecFromAlg(name)
		if err != nil {
			diags.AddAttributeError(path.Root("algs"), "Invalid algorithm", err.Error())

			return nil, false
		}

		specs = append(specs, spec)
	}

	return specs, true
}
