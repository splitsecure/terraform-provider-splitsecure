package saml2

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"strconv"
	"time"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	vaultusev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultres"
)

var (
	_ resource.Resource                = (*saml2IdentityProvider)(nil)
	_ resource.ResourceWithImportState = (*saml2IdentityProvider)(nil)
)

var errUnexpectedKind = errors.New("record is not a SAML2 identity provider")

type saml2IdentityProvider struct {
	client *client.Client
}

type saml2IdentityProviderModel struct {
	ID                    types.String `tfsdk:"id"`
	VaultID               types.String `tfsdk:"vault_id"`
	Name                  types.String `tfsdk:"name"`
	Description           types.String `tfsdk:"description"`
	NotBefore             types.String `tfsdk:"not_before"`
	NotAfter              types.String `tfsdk:"not_after"`
	NotificationPolicy    types.String `tfsdk:"notification_policy"`
	Sensitivity           types.String `tfsdk:"sensitivity"`
	Folder                types.List   `tfsdk:"folder"`
	FolderID              types.String `tfsdk:"folder_id"`
	Justification         types.String `tfsdk:"justification"`
	Wait                  types.String `tfsdk:"wait"`
	ProviderID            types.String `tfsdk:"provider_id"`
	SSOURLRedirect        types.String `tfsdk:"sso_url_redirect"`
	SSOURLPost            types.String `tfsdk:"sso_url_post"`
	MetadataXML           types.String `tfsdk:"metadata_xml"`
	SigningCertificatePEM types.String `tfsdk:"signing_certificate_pem"`
	SigningCertificateDER types.String `tfsdk:"signing_certificate_der"`
	SigningPublicKeyPEM   types.String `tfsdk:"signing_public_key_pem"`
	SigningPublicKeyDER   types.String `tfsdk:"signing_public_key_der"`
	IDPSerial             types.String `tfsdk:"idp_serial"`
}

// NewIdentityProviderResource returns a factory for the SAML2 IdP resource.
func NewIdentityProviderResource() resource.Resource {
	return &saml2IdentityProvider{}
}

func (r *saml2IdentityProvider) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_saml2_identity_provider"
}

func (r *saml2IdentityProvider) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	r.client = vaultres.ClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (r *saml2IdentityProvider) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	attrs := vaultres.CommonAttributes("identity provider")

	attrs["not_before"] = schema.StringAttribute{
		Optional:      true,
		Computed:      true,
		Description:   "Start of the signing certificate validity, as an RFC 3339 timestamp. Defaults to the server's choice. Changing it replaces the resource.",
		PlanModifiers: append(vaultres.ComputedOnce(), replaceUnlessSameInstant()),
		Validators:    []validator.String{vaultres.RFC3339Validator()},
	}
	attrs["not_after"] = schema.StringAttribute{
		Optional:      true,
		Computed:      true,
		Description:   "End of the signing certificate validity, as an RFC 3339 timestamp. Defaults to the server's choice. Changing it replaces the resource.",
		PlanModifiers: append(vaultres.ComputedOnce(), replaceUnlessSameInstant()),
		Validators:    []validator.String{vaultres.RFC3339Validator()},
	}

	computed := map[string]string{
		"provider_id":             "SAML EntityID used in the signing certificate subject, the assertion issuer and the metadata entityID.",
		"sso_url_redirect":        "Single sign-on URL for the HTTP-Redirect binding.",
		"sso_url_post":            "Single sign-on URL for the HTTP-POST binding.",
		"metadata_xml":            "SAML IdP metadata document built from the signing certificate, provider_id and SSO URLs. Suitable for aws_iam_saml_provider.",
		"signing_certificate_pem": "PEM-encoded X.509 signing certificate the IdP attaches to assertions.",
		"signing_certificate_der": "Base64-encoded DER of the signing certificate, the bytes between the markers of signing_certificate_pem.",
		"signing_public_key_pem":  "PEM-encoded SubjectPublicKeyInfo of the signing certificate, for service providers that pin a bare public key.",
		"signing_public_key_der":  "Base64-encoded SubjectPublicKeyInfo DER, the bytes between the markers of signing_public_key_pem.",
		"idp_serial":              "Serial number of the signing certificate issued to this IdP, in decimal.",
	}
	for name, description := range computed {
		attrs[name] = schema.StringAttribute{
			Computed:      true,
			Description:   description,
			PlanModifiers: vaultres.ComputedOnce(),
		}
	}

	resp.Schema = schema.Schema{
		Description: "SAML2 identity provider in a SplitSecure vault. Creating or deleting it may need approval, and the call waits for it. " +
			"Changing the folder moves the record in place. Changing any other input replaces the resource.",
		Attributes: attrs,
	}
}

func (r *saml2IdentityProvider) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan saml2IdentityProviderModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)

	if resp.Diagnostics.HasError() {
		return
	}

	opts := vaultres.WriteOptionsFromConfig(ctx, req.Config, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	parentID, ok := vaultres.ParentNode(ctx, r.client.VaultBrowse, plan.VaultID.ValueString(), plan.Folder, plan.FolderID, &resp.Diagnostics)
	if !ok {
		return
	}

	base := &vaultusev1.CreateSAML2IDPRequest_Base{
		VaultId: plan.VaultID.ValueString(),
		Common: vaultapi.CreateCommon(vaultapi.CreateCommonInput{
			Name:               plan.Name.ValueString(),
			Description:        plan.Description.ValueString(),
			NotificationPolicy: plan.NotificationPolicy.ValueString(),
			Sensitivity:        plan.Sensitivity.ValueString(),
			ParentNodeID:       parentID,
		}),
		Options: opts,
	}

	if !setValidity(base, &plan, &resp.Diagnostics) {
		return
	}

	created, err := r.client.VaultUse.CreateSAML2IDP(ctx, connect.NewRequest(&vaultusev1.CreateSAML2IDPRequest{Base: base}))
	if err != nil {
		resp.Diagnostics.AddError("Creating SAML2 IdP", err.Error())

		return
	}

	result, err := vaultapi.AwaitCreate(ctx, r.client.VaultUse, plan.VaultID.ValueString(), created.Msg.GetOutcome())
	if result != nil {
		// Record both ids now so a later error taints the created IdP instead of orphaning it.
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), result.GetSecretId())...)
		resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vault_id"), plan.VaultID)...)
	}

	if err != nil {
		resp.Diagnostics.AddError("Creating SAML2 IdP", err.Error())

		return
	}

	plan.ID = types.StringValue(result.GetSecretId())

	rec, err := vaultapi.FetchRecord(ctx, r.client.VaultBrowse, plan.VaultID.ValueString(), plan.ID.ValueString())
	if err == nil {
		err = populate(&plan, rec)
	}

	if err != nil {
		resp.Diagnostics.AddError("Reading new SAML2 IdP", err.Error())

		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *saml2IdentityProvider) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state saml2IdentityProviderModel

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
		resp.Diagnostics.AddError("Reading SAML2 IdP", err.Error())

		return
	}

	err = populate(&state, rec)
	if err != nil {
		resp.Diagnostics.AddError("Reading SAML2 IdP", err.Error())

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

func (r *saml2IdentityProvider) Update(ctx context.Context, req resource.UpdateRequest, resp *resource.UpdateResponse) {
	var plan, state saml2IdentityProviderModel

	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	// A bound written in another format is the same instant, so MoveRecord compares it in the state's format.
	resp.Diagnostics.Append(req.Plan.SetAttribute(ctx, path.Root("not_before"), state.NotBefore)...)
	resp.Diagnostics.Append(req.Plan.SetAttribute(ctx, path.Root("not_after"), state.NotAfter)...)

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
	state.NotBefore = plan.NotBefore
	state.NotAfter = plan.NotAfter

	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *saml2IdentityProvider) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state saml2IdentityProviderModel

	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)

	if resp.Diagnostics.HasError() {
		return
	}

	vaultID := state.VaultID.ValueString()

	deleted, err := r.client.VaultUse.Delete(ctx, connect.NewRequest(&vaultusev1.DeleteRequest{
		Base: &vaultusev1.DeleteRequest_Base{
			VaultId:  vaultID,
			SecretId: state.ID.ValueString(),
			Options:  vaultres.DestroyOptions("SAML2 IdP", state.Name.ValueString()),
		},
	}))
	if vaultapi.IsNotFound(err) {
		return
	}

	if err != nil {
		resp.Diagnostics.AddError("Deleting SAML2 IdP", err.Error())

		return
	}

	err = vaultapi.AwaitDelete(ctx, r.client.VaultUse, vaultID, deleted.Msg.GetOutcome())
	if err != nil {
		resp.Diagnostics.AddError("Deleting SAML2 IdP", err.Error())
	}
}

func (r *saml2IdentityProvider) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	vaultID, id, ok := vaultres.SplitImportID(req.ID)
	if !ok {
		resp.Diagnostics.AddError("Invalid import id", fmt.Sprintf("expected vault_id/id, got %q", req.ID))

		return
	}

	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("vault_id"), vaultID)...)
	resp.Diagnostics.Append(resp.State.SetAttribute(ctx, path.Root("id"), id)...)
}

func setValidity(base *vaultusev1.CreateSAML2IDPRequest_Base, plan *saml2IdentityProviderModel, diags *diag.Diagnostics) bool {
	var err error

	base.NotBefore, err = timestampFromString(plan.NotBefore)
	if err != nil {
		diags.AddAttributeError(path.Root("not_before"), "Invalid not_before", err.Error())

		return false
	}

	base.NotAfter, err = timestampFromString(plan.NotAfter)
	if err != nil {
		diags.AddAttributeError(path.Root("not_after"), "Invalid not_after", err.Error())

		return false
	}

	return true
}

// replaceUnlessSameInstant replaces the resource when a validity bound moves to another instant, not when only its format differs.
func replaceUnlessSameInstant() planmodifier.String {
	const description = "Replaces the resource when the bound is another instant."

	return stringplanmodifier.RequiresReplaceIf(func(_ context.Context, req planmodifier.StringRequest, resp *stringplanmodifier.RequiresReplaceIfFuncResponse) {
		resp.RequiresReplace = !sameInstant(req.PlanValue.ValueString(), req.StateValue.ValueString())
	}, description, description)
}

func sameInstant(a, b string) bool {
	ta, errA := time.Parse(time.RFC3339, a)
	tb, errB := time.Parse(time.RFC3339, b)

	return errA == nil && errB == nil && ta.Equal(tb)
}

func timestampFromString(s types.String) (*timestamppb.Timestamp, error) {
	if s.IsNull() || s.IsUnknown() || s.ValueString() == "" {
		return nil, nil //nolint:nilnil // an unset timestamp is a valid request value.
	}

	t, err := time.Parse(time.RFC3339, s.ValueString())
	if err != nil {
		return nil, fmt.Errorf("parsing timestamp: %w", err)
	}

	return timestamppb.New(t), nil
}

// populate fills the model from a fetched record. Configured validity bounds are kept as written.
func populate(m *saml2IdentityProviderModel, rec *vaultapi.Record) error {
	if rec.Kind != vaultapi.KindSAML2IDP {
		return fmt.Errorf("%w: kind %q", errUnexpectedKind, rec.Kind)
	}

	idp, err := vaultapi.DecodeIdP(rec.Params)
	if err != nil {
		return err
	}

	attrs := rec.Attributes
	m.Name = types.StringValue(attrs.GetName())
	m.Description = types.StringValue(attrs.GetDescription())
	m.NotificationPolicy = types.StringValue(vaultapi.NotificationPolicyToString(attrs.GetNotificationPolicy()))
	m.Sensitivity = vaultres.SensitivityState(vaultapi.SensitivityToString(attrs.GetSensitivity()))

	m.ProviderID = types.StringValue(idp.GetProviderId())
	m.SSOURLRedirect = types.StringValue(idp.GetSsoUrl())
	m.SSOURLPost = types.StringValue(idp.GetSsoUrlPost())
	m.IDPSerial = types.StringValue(strconv.FormatUint(idp.GetIdpSerial(), 10))

	metadata, err := idpMetadataXML(idp)
	if err != nil {
		return fmt.Errorf("rendering metadata: %w", err)
	}

	m.MetadataXML = types.StringValue(string(metadata))

	der := idp.GetX509Certificate()
	m.SigningCertificateDER = types.StringValue(base64.StdEncoding.EncodeToString(der))
	m.SigningCertificatePEM = types.StringValue(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))

	cert, err := x509.ParseCertificate(der)
	if err != nil {
		return fmt.Errorf("parsing signing certificate: %w", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		return fmt.Errorf("marshaling signing public key: %w", err)
	}

	m.SigningPublicKeyDER = types.StringValue(base64.StdEncoding.EncodeToString(spki))
	m.SigningPublicKeyPEM = types.StringValue(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spki})))

	if m.NotBefore.IsNull() || m.NotBefore.IsUnknown() {
		m.NotBefore = types.StringValue(cert.NotBefore.UTC().Format(time.RFC3339))
	}

	if m.NotAfter.IsNull() || m.NotAfter.IsUnknown() {
		m.NotAfter = types.StringValue(cert.NotAfter.UTC().Format(time.RFC3339))
	}

	return nil
}
