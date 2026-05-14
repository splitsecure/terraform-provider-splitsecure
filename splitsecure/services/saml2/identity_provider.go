package saml2

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"strings"

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
	"google.golang.org/protobuf/proto"

	conveniencestorev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/conveniencestore/v1"
	saml2v2 "github.com/splitsecure/apis/gen/go/proto/splitsecure/saml2/v2"
	teamresourcev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/teamresource/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

var (
	_ resource.Resource                = (*saml2IdentityProvider)(nil)
	_ resource.ResourceWithImportState = (*saml2IdentityProvider)(nil)
)

type saml2IdentityProvider struct {
	client *client.Client
}

type saml2IdentityProviderModel struct {
	ID                    types.String `tfsdk:"id"`
	TeamS2R               types.String `tfsdk:"team_s2r"`
	ProviderID            types.String `tfsdk:"provider_id"`
	Name                  types.String `tfsdk:"name"`
	Description           types.String `tfsdk:"description"`
	NotificationPolicy    types.String `tfsdk:"notification_policy"`
	SSOURLRedirect        types.String `tfsdk:"sso_url_redirect"`
	SSOURLPost            types.String `tfsdk:"sso_url_post"`
	Justification         types.String `tfsdk:"justification"`
	MetadataXML           types.String `tfsdk:"metadata_xml"`
	SigningCertificatePEM types.String `tfsdk:"signing_certificate_pem"`
	SigningCertificateDER types.String `tfsdk:"signing_certificate_der"`
	SigningPublicKeyPEM   types.String `tfsdk:"signing_public_key_pem"`
	SigningPublicKeyDER   types.String `tfsdk:"signing_public_key_der"`
}

// NewIdentityProvider returns a factory for the SAML2 IdP resource.
func NewIdentityProvider() resource.Resource {
	return &saml2IdentityProvider{}
}

func (r *saml2IdentityProvider) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_saml2_identity_provider"
}

func (r *saml2IdentityProvider) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
	if req.ProviderData == nil {
		return
	}
	c, ok := req.ProviderData.(*client.Client)
	if !ok {
		resp.Diagnostics.AddError(
			"Unexpected provider data type",
			fmt.Sprintf("expected *client.Client, got %T", req.ProviderData),
		)

		return
	}
	r.client = c
}

// forceNewString is the plan-modifier applied to every writable
// attribute. There is no in-place update path for SAML2 IdPs; every
// change replaces the resource (destroy + create, two proposals).
func forceNewString() []planmodifier.String {
	return []planmodifier.String{stringplanmodifier.RequiresReplace()}
}

func (r *saml2IdentityProvider) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "SAML2 identity provider on a SplitSecure team. Create/Delete go through the standard proposal flow; update is not supported (any writable-attribute change replaces the resource).",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Resource s2r URI of the identity provider.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"team_s2r": schema.StringAttribute{
				Required:      true,
				Description:   "Team s2r URI the identity provider lives on.",
				PlanModifiers: forceNewString(),
				Validators:    []validator.String{s2rKindValidator("team")},
			},
			"provider_id": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "SAML EntityID stamped into the cert subject, the assertion <Issuer>, and the metadata entityID. " +
					"Leave unset to get a server-generated https://<frontend-host>/saml/idp/<six-bip39-words> " +
					"identifier (matches the web UI). Set explicitly for a stable URN-form EntityID.",
				PlanModifiers: forceNewString(),
			},
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "Human-readable IdP name.",
				PlanModifiers: forceNewString(),
				Validators: []validator.String{
					stringvalidator.LengthBetween(1, 256),
				},
			},
			"description": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "Free-form description.",
				PlanModifiers: forceNewString(),
				Validators: []validator.String{
					stringvalidator.LengthAtMost(1024),
				},
			},
			"notification_policy": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "Notification policy for proposals against this IdP. One of: " + strings.Join(notificationPolicyValues(), ", ") + ". Defaults to \"notify_everyone\".",
				PlanModifiers: forceNewString(),
				Validators: []validator.String{
					stringvalidator.OneOf(notificationPolicyValues()...),
				},
			},
			"sso_url_redirect": schema.StringAttribute{
				Computed:      true,
				Description:   "Single sign-on URL (HTTP-Redirect binding). Server-assigned; not user-configurable.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"sso_url_post": schema.StringAttribute{
				Computed:      true,
				Description:   "Single sign-on URL (HTTP-POST binding). Server-assigned; not user-configurable.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"justification": schema.StringAttribute{
				Optional:  true,
				WriteOnly: true,
				Description: "Justification text rendered to voters during the create proposal. Write-only -- never persisted to state. " +
					"The delete proposal sends a generated 'terraform destroy' justification, so callers don't need to keep this set " +
					"after the resource exists.",
				Validators: []validator.String{
					stringvalidator.LengthAtMost(4096),
				},
			},
			"metadata_xml": schema.StringAttribute{
				Computed:    true,
				Description: "SAML IdP metadata document built from the IdP's signing certificate, provider_id, and SSO URLs. Suitable for aws_iam_saml_provider.",
			},
			"signing_certificate_pem": schema.StringAttribute{
				Computed:    true,
				Description: "PEM-encoded X.509 signing certificate the IdP attaches to assertions. Suitable for SPs that take the raw certificate (e.g. tls_certificate-style consumers, custom SAML stacks).",
			},
			"signing_certificate_der": schema.StringAttribute{
				Computed: true,
				Description: "Base64-encoded DER X.509 signing certificate -- the same bytes as the contents of `signing_certificate_pem` between its " +
					"BEGIN/END markers. Use this when a downstream consumer wants the unwrapped certificate body " +
					"(e.g. the `<X509Certificate>` element of an SP metadata document).",
			},
			"signing_public_key_pem": schema.StringAttribute{
				Computed:    true,
				Description: "PEM-encoded SubjectPublicKeyInfo extracted from the signing certificate. Suitable for SPs that pin a bare public key rather than the wrapping certificate.",
			},
			"signing_public_key_der": schema.StringAttribute{
				Computed:    true,
				Description: "Base64-encoded SubjectPublicKeyInfo DER -- the bytes between the BEGIN/END markers of `signing_public_key_pem`.",
			},
		},
	}
}

func (r *saml2IdentityProvider) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan saml2IdentityProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Justification is WriteOnly, so its value lives on req.Config
	// rather than req.Plan; reading it from the plan would always
	// yield null and the proposal would ship with no justification.
	var config saml2IdentityProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	genResp, err := r.client.ConvenienceStoreService.GenerateCreateSAML2IdentityProviderProposal(ctx, connect.NewRequest(&conveniencestorev1.GenerateCreateSAML2IdentityProviderProposalRequest{
		Base: &conveniencestorev1.GenerateCreateSAML2IdentityProviderProposalRequest_Base{
			TeamS2R: plan.TeamS2R.ValueString(),
			Idp: &saml2v2.IdPState{
				ProviderId: plan.ProviderID.ValueString(),
				BaseResourceAttributes: &teamresourcev1.BaseResourceAttributes{
					Name:               plan.Name.ValueString(),
					Description:        plan.Description.ValueString(),
					NotificationPolicy: notificationPolicyFromString(plan.NotificationPolicy.ValueString()),
				},
			},
			Justification: config.Justification.ValueString(),
		},
	}))
	if err != nil {
		resp.Diagnostics.AddError("GenerateCreateSAML2IdentityProviderProposal", err.Error())

		return
	}

	resourceS2R, err := sendAndAwaitResource(ctx, r.client, r.client.OrgS2R, genResp.Msg.GetInvokeRequest(), 0)
	if err != nil {
		resp.Diagnostics.AddError("Creating SAML2 IdP", err.Error())

		return
	}

	rec, err := fetchSAML2Record(ctx, r.client, resourceS2R)
	if err != nil {
		resp.Diagnostics.AddError("Fetching newly created SAML2 IdP", err.Error())

		return
	}
	if rec == nil {
		resp.Diagnostics.AddError("Creating SAML2 IdP", fmt.Sprintf("record not found at %s after completion", resourceS2R))

		return
	}

	diags := populateIDPModel(&plan, resourceS2R, rec)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
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

	rec, err := fetchSAML2Record(ctx, r.client, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Reading SAML2 IdP", err.Error())

		return
	}
	if rec == nil || rec.GetContent().GetTombstone() != nil {
		resp.State.RemoveResource(ctx)

		return
	}

	diags := populateIDPModel(&state, state.ID.ValueString(), rec)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

// Update is not implemented -- every writable attribute has
// RequiresReplace, so the framework always takes the destroy+create
// path rather than calling Update. Present only to satisfy the
// resource.Resource interface.
func (r *saml2IdentityProvider) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"Update not supported",
		"splitsecure_saml2_identity_provider has no in-place update path; every writable attribute forces replacement.",
	)
}

func (r *saml2IdentityProvider) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state saml2IdentityProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	genResp, err := r.client.ConvenienceStoreService.GenerateDeleteSAML2IdentityProviderProposal(ctx, connect.NewRequest(&conveniencestorev1.GenerateDeleteSAML2IdentityProviderProposalRequest{
		Base: &conveniencestorev1.GenerateDeleteSAML2IdentityProviderProposalRequest_Base{
			ResourceS2R:   state.ID.ValueString(),
			Justification: destroyJustification("SAML2 IdP", state.Name.ValueString(), state.ID.ValueString()),
		},
	}))
	if err != nil {
		resp.Diagnostics.AddError("GenerateDeleteSAML2IdentityProviderProposal", err.Error())

		return
	}

	err = sendAndAwaitDelete(ctx, r.client, r.client.OrgS2R, genResp.Msg.GetInvokeRequest(), 0)
	if err != nil {
		resp.Diagnostics.AddError("Deleting SAML2 IdP", err.Error())

		return
	}
}

func (r *saml2IdentityProvider) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import id is the resource_s2r. team_s2r is reconstructed from
	// it by populateIDPModel on Read (s2r:{deployment}:saml2idp:
	// {team}/{resource} -> s2r:{deployment}:team:{team}), so a
	// fresh import is plan-idempotent without state surgery.
	// org_s2r lives on the provider.
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// populateIDPModel fills the state model from a fetched record. Writes
// the resource_s2r into ID, decodes the authenticated IdPState,
// populates computed attributes, and renders metadata_xml.
func populateIDPModel(m *saml2IdentityProviderModel, resourceS2R string, rec *conveniencestorev1.SAML2ResourceRecord) diag.Diagnostics {
	signed := rec.GetContent().GetUpdateableRecord().GetContent().GetSignedIdp()
	if signed == nil {
		var d diag.Diagnostics
		d.AddError("Decoding SAML2 IdP", "record has no signed_idp content")

		return d
	}

	var state saml2v2.IdPStateAndKey
	err := proto.Unmarshal(signed.GetAuthenticated(), &state)
	if err != nil {
		var d diag.Diagnostics
		d.AddError("Decoding SAML2 IdP", fmt.Errorf("unmarshalling authenticated IdPStateAndKey: %w", err).Error())

		return d
	}
	idp := state.GetIdpState()

	m.ID = types.StringValue(resourceS2R)
	if teamS2R := teamS2RFromResourceS2R(resourceS2R); teamS2R != "" {
		m.TeamS2R = types.StringValue(teamS2R)
	}
	bra := idp.GetBaseResourceAttributes()
	m.ProviderID = types.StringValue(idp.GetProviderId())
	m.Name = types.StringValue(bra.GetName())
	m.Description = types.StringValue(bra.GetDescription())
	m.NotificationPolicy = types.StringValue(notificationPolicyToString(bra.GetNotificationPolicy()))
	m.SSOURLRedirect = types.StringValue(idp.GetSsoUrl())
	m.SSOURLPost = types.StringValue(idp.GetSsoUrlPost())

	// Render metadata_xml from the structured fields. validUntil is
	// anchored to the cert's NotAfter so refresh is idempotent.
	xmlBytes, err := idpMetadataXML(idp)
	if err != nil {
		var d diag.Diagnostics
		d.AddError("Rendering SAML2 IdP metadata", err.Error())

		return d
	}
	m.MetadataXML = types.StringValue(string(xmlBytes))

	der := idp.GetX509Certificate()
	m.SigningCertificateDER = types.StringValue(base64.StdEncoding.EncodeToString(der))
	m.SigningCertificatePEM = types.StringValue(string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})))

	// Cert parse + SPKI marshal cannot realistically fail here -- idpMetadataXML
	// already required a parseable cert -- but surface errors explicitly rather
	// than silently producing empty public-key attributes.
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		var d diag.Diagnostics
		d.AddError("Parsing SAML2 IdP signing certificate", err.Error())

		return d
	}
	spkiDER, err := x509.MarshalPKIXPublicKey(cert.PublicKey)
	if err != nil {
		var d diag.Diagnostics
		d.AddError("Marshaling SAML2 IdP signing public key", err.Error())

		return d
	}
	m.SigningPublicKeyDER = types.StringValue(base64.StdEncoding.EncodeToString(spkiDER))
	m.SigningPublicKeyPEM = types.StringValue(string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: spkiDER})))

	return nil
}
