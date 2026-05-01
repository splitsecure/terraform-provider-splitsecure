package saml2

import (
	"context"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/objectplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/planmodifier"
	"github.com/hashicorp/terraform-plugin-framework/resource/schema/stringplanmodifier"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"google.golang.org/protobuf/proto"

	conveniencestorev1 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/conveniencestore/v1"
	saml2v2 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/enclaveservices/saml2/v2"
	teamresourcev1 "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/teamresource/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

var (
	_ resource.Resource                   = (*saml2ServiceProvider)(nil)
	_ resource.ResourceWithImportState    = (*saml2ServiceProvider)(nil)
	_ resource.ResourceWithValidateConfig = (*saml2ServiceProvider)(nil)
)

// Account kind tokens. Mirror the proto oneof field names exactly so
// the HCL `account.kind` value can drive both validator + per-variant
// dispatch without a separate mapping table.
const (
	kindAWS                   = "aws"
	kindCloudflare            = "cloudflare"
	kindEventBrite            = "event_brite"
	kindGCP                   = "gcp"
	kindGoogleWorkspace       = "google_workspace"
	kindGoogleWorkspaceLegacy = "google_workspace_legacy"
	kindIBMCloud              = "ibm_cloud"
	kindKandji                = "kandji"
	kindMicrosoftEntraID      = "microsoft_entra_id"
	kindOkta                  = "okta"
	kindOracleCloud           = "oracle_cloud"
	kindPagerDuty             = "pager_duty"
	kindPitchBook             = "pitch_book"
	kindRapid7                = "rapid7"
	kindStripe                = "stripe"
	kindVeeam                 = "veeam"
	kindWorkday               = "workday"
)

// spAccountKinds returns the canonical list of account.kind values.
// Callers pass the result to stringvalidator.OneOf for schema-level
// validation and to strings.Join for the schema description, so the
// set stays in one place.
func spAccountKinds() []string {
	return []string{
		kindAWS,
		kindCloudflare,
		kindEventBrite,
		kindGCP,
		kindGoogleWorkspace,
		kindGoogleWorkspaceLegacy,
		kindIBMCloud,
		kindKandji,
		kindMicrosoftEntraID,
		kindOkta,
		kindOracleCloud,
		kindPagerDuty,
		kindPitchBook,
		kindRapid7,
		kindStripe,
		kindVeeam,
		kindWorkday,
	}
}

type saml2ServiceProvider struct {
	client *client.Client
}

// saml2ServiceProviderModel is the schema Terraform sees.
type saml2ServiceProviderModel struct {
	ID                 types.String  `tfsdk:"id"`
	TeamS2R            types.String  `tfsdk:"team_s2r"`
	IdpResourceS2R     types.String  `tfsdk:"idp_resource_s2r"`
	Name               types.String  `tfsdk:"name"`
	Description        types.String  `tfsdk:"description"`
	NotificationPolicy types.String  `tfsdk:"notification_policy"`
	Sensitivity        types.String  `tfsdk:"sensitivity"`
	EntityID           types.String  `tfsdk:"entity_id"`
	ACSURL             types.String  `tfsdk:"acs_url"`
	Justification      types.String  `tfsdk:"justification"`
	AccountType        types.String  `tfsdk:"account_type"`
	Account            *accountModel `tfsdk:"account"`
}

// accountModel mirrors saml2v2.SAML2ServiceProvider's account oneof.
// Kind selects the variant; the matching sub-block carries its
// parameters. Mismatched kind + sub-block is a validation error.
type accountModel struct {
	Kind types.String `tfsdk:"kind"`

	AWS                   *accountAWSModel                   `tfsdk:"aws"`
	Cloudflare            *accountCloudflareModel            `tfsdk:"cloudflare"`
	EventBrite            *accountEventBriteModel            `tfsdk:"event_brite"`
	GCP                   *accountGCPModel                   `tfsdk:"gcp"`
	GoogleWorkspace       *accountGoogleWorkspaceModel       `tfsdk:"google_workspace"`
	GoogleWorkspaceLegacy *accountGoogleWorkspaceLegacyModel `tfsdk:"google_workspace_legacy"`
	IBMCloud              *accountIBMCloudModel              `tfsdk:"ibm_cloud"`
	Kandji                *accountKandjiModel                `tfsdk:"kandji"`
	MicrosoftEntraID      *accountMicrosoftEntraIDModel      `tfsdk:"microsoft_entra_id"`
	Okta                  *accountOktaModel                  `tfsdk:"okta"`
	OracleCloud           *accountOracleCloudModel           `tfsdk:"oracle_cloud"`
	PagerDuty             *accountPagerDutyModel             `tfsdk:"pager_duty"`
	PitchBook             *accountPitchBookModel             `tfsdk:"pitch_book"`
	Rapid7                *accountRapid7Model                `tfsdk:"rapid7"`
	Stripe                *accountStripeModel                `tfsdk:"stripe"`
	Veeam                 *accountVeeamModel                 `tfsdk:"veeam"`
	Workday               *accountWorkdayModel               `tfsdk:"workday"`
}

// Account variant models, alphabetized. One named type per
// integration so the block's identity lives in the type name;
// zero-attribute variants have their own type so adding a field
// later is isolated.

type accountAWSModel struct {
	SAMLProviderARN types.String `tfsdk:"saml_provider_arn"`
	AllowedRoleARNs types.List   `tfsdk:"allowed_role_arns"`
}

type accountCloudflareModel struct {
	SSOEndpoint  types.String `tfsdk:"sso_endpoint"`
	DefaultEmail types.String `tfsdk:"default_email"`
}

type accountEventBriteModel struct{}

type accountGCPModel struct {
	DefaultEmail types.String `tfsdk:"default_email"`
}

type accountGoogleWorkspaceModel struct{}

type accountGoogleWorkspaceLegacyModel struct {
	DefaultEmail types.String `tfsdk:"default_email"`
	DomainName   types.String `tfsdk:"domain_name"`
}

type accountIBMCloudModel struct {
	LoginURL types.String `tfsdk:"login_url"`
}

type accountKandjiModel struct {
	DefaultEmail types.String `tfsdk:"default_email"`
}

type accountMicrosoftEntraIDModel struct{}

type accountOktaModel struct {
	AllowedEmails types.List `tfsdk:"allowed_emails"`
}

type accountOracleCloudModel struct{}

type accountPagerDutyModel struct{}

type accountPitchBookModel struct{}

type accountRapid7Model struct {
	DefaultRelayState types.String `tfsdk:"default_relay_state"`
	DefaultEmail      types.String `tfsdk:"default_email"`
	DefaultFirstName  types.String `tfsdk:"default_first_name"`
	DefaultLastName   types.String `tfsdk:"default_last_name"`
	DefaultRBACGroups types.List   `tfsdk:"default_rbac_groups"`
}

type accountStripeModel struct {
	AccountID types.String `tfsdk:"account_id"`
}

type accountVeeamModel struct{}

type accountWorkdayModel struct{}

// NewServiceProvider returns a factory for the SAML2 SP resource.
func NewServiceProvider() resource.Resource {
	return &saml2ServiceProvider{}
}

func (r *saml2ServiceProvider) Metadata(_ context.Context, req resource.MetadataRequest, resp *resource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_saml2_service_provider"
}

func (r *saml2ServiceProvider) Configure(_ context.Context, req resource.ConfigureRequest, resp *resource.ConfigureResponse) {
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

// ValidateConfig enforces account.kind and the selected sub-block
// stay in sync: exactly the sub-block matching kind must be set,
// and no others. Caught at `terraform plan` time instead of Create.
func (r *saml2ServiceProvider) ValidateConfig(ctx context.Context, req resource.ValidateConfigRequest, resp *resource.ValidateConfigResponse) {
	var cfg saml2ServiceProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &cfg)...)
	if resp.Diagnostics.HasError() || cfg.Account == nil {
		return
	}

	kind := cfg.Account.Kind.ValueString()
	if kind == "" {
		return // handled by OneOf on kind attribute
	}

	// Map each kind to the sub-block that must be non-nil. All others
	// must be nil; a mismatch is a validation error.
	type check struct {
		name string
		set  bool
	}
	checks := []check{
		{kindAWS, cfg.Account.AWS != nil},
		{kindCloudflare, cfg.Account.Cloudflare != nil},
		{kindEventBrite, cfg.Account.EventBrite != nil},
		{kindGCP, cfg.Account.GCP != nil},
		{kindGoogleWorkspace, cfg.Account.GoogleWorkspace != nil},
		{kindGoogleWorkspaceLegacy, cfg.Account.GoogleWorkspaceLegacy != nil},
		{kindIBMCloud, cfg.Account.IBMCloud != nil},
		{kindKandji, cfg.Account.Kandji != nil},
		{kindMicrosoftEntraID, cfg.Account.MicrosoftEntraID != nil},
		{kindOkta, cfg.Account.Okta != nil},
		{kindOracleCloud, cfg.Account.OracleCloud != nil},
		{kindPagerDuty, cfg.Account.PagerDuty != nil},
		{kindPitchBook, cfg.Account.PitchBook != nil},
		{kindRapid7, cfg.Account.Rapid7 != nil},
		{kindStripe, cfg.Account.Stripe != nil},
		{kindVeeam, cfg.Account.Veeam != nil},
		{kindWorkday, cfg.Account.Workday != nil},
	}

	for _, c := range checks {
		switch {
		case c.name == kind && !c.set:
			resp.Diagnostics.AddAttributeError(
				path.Root("account").AtName(kind),
				"missing sub-block for account.kind",
				"account.kind = "+kind+` requires the "`+kind+`" sub-block to be present`,
			)
		case c.name != kind && c.set:
			resp.Diagnostics.AddAttributeError(
				path.Root("account").AtName(c.name),
				"account sub-block does not match account.kind",
				"account.kind = "+kind+` but the "`+c.name+`" sub-block is set; remove it or change kind`,
			)
		}
	}

	// Per-kind required attributes. Schema marks them Optional so
	// empty sibling blocks don't force the user to set fields they
	// don't need; required-ness is enforced here only for the
	// matching kind.
	validateRequiredForKind(cfg.Account, kind, &resp.Diagnostics)
}

// validateRequiredForKind enforces the "required when kind=X" rule
// on the sub-block attributes. Only fields that are genuinely
// required by the server-side SAML2ServiceProvider variant are
// checked here.
//
//nolint:cyclop // one branch per account variant with required fields.
func validateRequiredForKind(a *accountModel, kind string, diags *diag.Diagnostics) {
	required := func(p path.Path, got types.String, label string) {
		// Skip unknowns: computed values from other resources are
		// resolved at apply time, and the null/empty check here
		// would incorrectly flag them during plan.
		if got.IsUnknown() {
			return
		}
		if got.IsNull() || got.ValueString() == "" {
			diags.AddAttributeError(p, "required attribute", label+" is required when account.kind = \""+kind+"\"")
		}
	}
	base := path.Root("account")
	switch kind {
	case kindAWS:
		if a.AWS != nil {
			required(base.AtName(kindAWS).AtName("saml_provider_arn"), a.AWS.SAMLProviderARN, "account.aws.saml_provider_arn")
			p := base.AtName(kindAWS).AtName("allowed_role_arns")
			// List{IsUnknown} during plan-time reads through known elements in
			// the next pass, so the empty-list guard only fires on a statically
			// empty or null list -- the common mistake we want to catch.
			if !a.AWS.AllowedRoleARNs.IsUnknown() && len(a.AWS.AllowedRoleARNs.Elements()) == 0 {
				diags.AddAttributeError(p, "required attribute", "account.aws.allowed_role_arns is required when account.kind = \"aws\"")
			}
		}
	case kindCloudflare:
		if a.Cloudflare != nil {
			required(base.AtName(kindCloudflare).AtName("sso_endpoint"), a.Cloudflare.SSOEndpoint, "account."+kindCloudflare+".sso_endpoint")
		}
	case kindGoogleWorkspaceLegacy:
		if a.GoogleWorkspaceLegacy != nil {
			required(base.AtName(kindGoogleWorkspaceLegacy).AtName("domain_name"), a.GoogleWorkspaceLegacy.DomainName, "account."+kindGoogleWorkspaceLegacy+".domain_name")
		}
	case kindIBMCloud:
		if a.IBMCloud != nil {
			required(base.AtName(kindIBMCloud).AtName("login_url"), a.IBMCloud.LoginURL, "account."+kindIBMCloud+".login_url")
		}
	case kindStripe:
		if a.Stripe != nil {
			required(base.AtName(kindStripe).AtName("account_id"), a.Stripe.AccountID, "account."+kindStripe+".account_id")
		}
	}
}

func (r *saml2ServiceProvider) Schema(_ context.Context, _ resource.SchemaRequest, resp *resource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "SAML2 service provider on a SplitSecure team. Create/Delete go through the proposal flow; updates replace the resource.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:      true,
				Description:   "Resource s2r URI of the service provider.",
				PlanModifiers: []planmodifier.String{stringplanmodifier.UseStateForUnknown()},
			},
			"team_s2r": schema.StringAttribute{
				Required:      true,
				Description:   "Team s2r URI the service provider lives on.",
				PlanModifiers: forceNewString(),
				Validators:    []validator.String{s2rKindValidator("team")},
			},
			"idp_resource_s2r": schema.StringAttribute{
				Required:      true,
				Description:   "Resource s2r URI of the IdP this SP binds to. Must be on the same team.",
				PlanModifiers: forceNewString(),
				Validators:    []validator.String{s2rKindValidator("saml2idp")},
			},
			"name": schema.StringAttribute{
				Required:      true,
				Description:   "Human-readable SP name.",
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
				Description:   "Notification policy for proposals against this SP. One of: " + strings.Join(notificationPolicyValues(), ", ") + ". Defaults to \"notify_everyone\".",
				PlanModifiers: forceNewString(),
				Validators: []validator.String{
					stringvalidator.OneOf(notificationPolicyValues()...),
				},
			},
			"sensitivity": schema.StringAttribute{
				Optional: true,
				Computed: true,
				Description: "Account sensitivity classification surfaced to voters. One of: " +
					strings.Join(sensitivityLevelValues(), ", ") + ". Empty / unset records as unspecified.",
				PlanModifiers: forceNewString(),
				Validators: []validator.String{
					stringvalidator.OneOf(sensitivityLevelValues()...),
				},
			},
			"entity_id": schema.StringAttribute{
				Optional:      true,
				Computed:      true,
				Description:   "SP entity ID (written into metadata.entity_descriptor.entity_id).",
				PlanModifiers: forceNewString(),
			},
			"acs_url": schema.StringAttribute{
				Required: true,
				Description: "Assertion-consumer-service URL — single SAML response endpoint hosted by the " +
					"integration (written into metadata.entity_descriptor.sp_sso_descriptor[0]." +
					"assertion_consumer_service[0].location). Format depends on the integration: " +
					"`https://signin.aws.amazon.com/saml` for AWS IAM Federation, `.../saml/acs/SAML<id>` " +
					"for AWS Identity Center, the per-tenant URL for Cloudflare / Okta / etc.",
				PlanModifiers: forceNewString(),
				Validators:    []validator.String{httpsURLValidator()},
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
			"account_type": schema.StringAttribute{
				Computed:    true,
				Description: "Name of the account variant selected by the `account` block.",
			},
		},
		Blocks: map[string]schema.Block{
			"account": spAccountBlock(),
		},
	}
}

func spAccountBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Description: "Selects one of the 17 supported SP integrations. `kind` names the variant; populate the matching sub-block with its parameters.",
		// SAML2 SPs have no in-place update path; any change to the
		// account block (kind switch, attribute add/remove on a sub-block)
		// must replace the resource via Delete+Create.
		PlanModifiers: []planmodifier.Object{objectplanmodifier.RequiresReplace()},
		Attributes: map[string]schema.Attribute{
			"kind": schema.StringAttribute{
				Required:    true,
				Description: "Integration variant. One of: " + strings.Join(spAccountKinds(), ", ") + ".",
				Validators: []validator.String{
					stringvalidator.OneOf(spAccountKinds()...),
				},
			},
		},
		Blocks: map[string]schema.Block{
			kindAWS:                   spAWSBlock(),
			kindCloudflare:            spCloudflareBlock(),
			kindEventBrite:            spEmptyBlock("EventBrite account."),
			kindGCP:                   spGCPBlock(),
			kindGoogleWorkspace:       spEmptyBlock("Google Workspace account."),
			kindGoogleWorkspaceLegacy: spGoogleWorkspaceLegacyBlock(),
			kindIBMCloud:              spIBMCloudBlock(),
			kindKandji:                spKandjiBlock(),
			kindMicrosoftEntraID:      spEmptyBlock("Microsoft Entra ID account."),
			kindOkta:                  spOktaBlock(),
			kindOracleCloud:           spEmptyBlock("Oracle Cloud account."),
			kindPagerDuty:             spEmptyBlock("PagerDuty account."),
			kindPitchBook:             spEmptyBlock("PitchBook account."),
			kindRapid7:                spRapid7Block(),
			kindStripe:                spStripeBlock(),
			kindVeeam:                 spEmptyBlock("Veeam account."),
			kindWorkday:               spEmptyBlock("Workday account."),
		},
	}
}

func spEmptyBlock(desc string) schema.SingleNestedBlock {
	return schema.SingleNestedBlock{Description: desc}
}

func spAWSBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Description: "AWS SAML provider integration.",
		Attributes: map[string]schema.Attribute{
			"saml_provider_arn": schema.StringAttribute{Optional: true, Description: "ARN of the aws_iam_saml_provider resource. Required when account.kind = \"aws\"."},
			"allowed_role_arns": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Role ARNs voters may assume through this service provider. Required when account.kind = \"aws\".",
			},
		},
	}
}

func spCloudflareBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Description: "Cloudflare access integration.",
		Attributes: map[string]schema.Attribute{
			"sso_endpoint": schema.StringAttribute{
				Optional:    true,
				Description: "Cloudflare SSO endpoint. Required when account.kind = \"cloudflare\".",
				Validators:  []validator.String{httpsURLValidator()},
			},
			"default_email": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Fallback email for asserted users.",
				Validators:  []validator.String{emailValidator()},
			},
		},
	}
}

func spGCPBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Description: "Google Cloud Platform SAML integration.",
		Attributes: map[string]schema.Attribute{
			"default_email": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Default email claim.",
				Validators:  []validator.String{emailValidator()},
			},
		},
	}
}

func spGoogleWorkspaceLegacyBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Description: "Legacy Google Workspace SAML integration.",
		Attributes: map[string]schema.Attribute{
			"default_email": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Default email claim.",
				Validators:  []validator.String{emailValidator()},
			},
			"domain_name": schema.StringAttribute{Optional: true, Description: "Google Workspace domain name. Required when account.kind = \"google_workspace_legacy\"."},
		},
	}
}

func spIBMCloudBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Description: "IBM Cloud SAML integration.",
		Attributes: map[string]schema.Attribute{
			"login_url": schema.StringAttribute{
				Optional:    true,
				Description: "IBM Cloud login URL. Required when account.kind = \"ibm_cloud\".",
				Validators:  []validator.String{httpsURLValidator()},
			},
		},
	}
}

func spKandjiBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Description: "Kandji SAML integration.",
		Attributes: map[string]schema.Attribute{
			"default_email": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Default email claim.",
				Validators:  []validator.String{emailValidator()},
			},
		},
	}
}

func spOktaBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Description: "Okta SAML integration.",
		Attributes: map[string]schema.Attribute{
			"allowed_emails": schema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType, Description: "Email allowlist."},
		},
	}
}

func spRapid7Block() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Description: "Rapid7 SAML integration.",
		Attributes: map[string]schema.Attribute{
			"default_relay_state": schema.StringAttribute{Optional: true, Computed: true, Description: "Default RelayState."},
			"default_email": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Default email claim.",
				Validators:  []validator.String{emailValidator()},
			},
			"default_first_name":  schema.StringAttribute{Optional: true, Computed: true, Description: "Default first-name claim."},
			"default_last_name":   schema.StringAttribute{Optional: true, Computed: true, Description: "Default last-name claim."},
			"default_rbac_groups": schema.ListAttribute{Optional: true, Computed: true, ElementType: types.StringType, Description: "Default RBAC groups."},
		},
	}
}

func spStripeBlock() schema.SingleNestedBlock {
	return schema.SingleNestedBlock{
		Description: "Stripe SAML integration.",
		Attributes: map[string]schema.Attribute{
			"account_id": schema.StringAttribute{Optional: true, Description: "Stripe account identifier. Required when account.kind = \"stripe\"."},
		},
	}
}

func (r *saml2ServiceProvider) Create(ctx context.Context, req resource.CreateRequest, resp *resource.CreateResponse) {
	var plan saml2ServiceProviderModel
	resp.Diagnostics.Append(req.Plan.Get(ctx, &plan)...)
	if resp.Diagnostics.HasError() {
		return
	}

	// Justification is WriteOnly, so its value lives on req.Config
	// rather than req.Plan; reading it from the plan would always
	// yield null and the proposal would ship with no justification.
	var config saml2ServiceProviderModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	base := &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base{
		TeamS2R:        plan.TeamS2R.ValueString(),
		IdpResourceS2R: plan.IdpResourceS2R.ValueString(),
		Attributes: &teamresourcev1.BaseResourceAttributes{
			Name:               plan.Name.ValueString(),
			Description:        plan.Description.ValueString(),
			NotificationPolicy: notificationPolicyFromString(plan.NotificationPolicy.ValueString()),
			Sensitivity:        sensitivityFromString(plan.Sensitivity.ValueString()),
		},
		EntityId:      plan.EntityID.ValueString(),
		AcsUrl:        plan.ACSURL.ValueString(),
		Justification: config.Justification.ValueString(),
	}

	accountType, diags := setAccountOnRequest(ctx, base, &plan)
	resp.Diagnostics.Append(diags...)
	if resp.Diagnostics.HasError() {
		return
	}

	genResp, err := r.client.ConvenienceStoreService.GenerateCreateSAML2ServiceProviderProposal(ctx, connect.NewRequest(&conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest{
		Base: base,
	}))
	if err != nil {
		resp.Diagnostics.AddError("GenerateCreateSAML2ServiceProviderProposal", err.Error())

		return
	}

	resourceS2R, err := sendAndAwaitResource(ctx, r.client, r.client.OrgS2R, genResp.Msg.GetInvokeRequest(), 0)
	if err != nil {
		resp.Diagnostics.AddError("Creating SAML2 SP", err.Error())

		return
	}

	rec, err := fetchSAML2Record(ctx, r.client, resourceS2R)
	if err != nil {
		resp.Diagnostics.AddError("Fetching newly created SAML2 SP", err.Error())

		return
	}
	if rec == nil {
		resp.Diagnostics.AddError("Creating SAML2 SP", fmt.Sprintf("record not found at %s after completion", resourceS2R))

		return
	}

	populateSPModel(ctx, &plan, resourceS2R, rec, accountType, &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &plan)...)
}

func (r *saml2ServiceProvider) Read(ctx context.Context, req resource.ReadRequest, resp *resource.ReadResponse) {
	var state saml2ServiceProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	rec, err := fetchSAML2Record(ctx, r.client, state.ID.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Reading SAML2 SP", err.Error())

		return
	}
	if rec == nil || rec.GetContent().GetTombstone() != nil {
		resp.State.RemoveResource(ctx)

		return
	}

	populateSPModel(ctx, &state, state.ID.ValueString(), rec, state.AccountType.ValueString(), &resp.Diagnostics)
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}

func (r *saml2ServiceProvider) Update(_ context.Context, _ resource.UpdateRequest, resp *resource.UpdateResponse) {
	resp.Diagnostics.AddError(
		"Update not supported",
		"splitsecure_saml2_service_provider has no in-place update path; every writable attribute forces replacement.",
	)
}

func (r *saml2ServiceProvider) Delete(ctx context.Context, req resource.DeleteRequest, resp *resource.DeleteResponse) {
	var state saml2ServiceProviderModel
	resp.Diagnostics.Append(req.State.Get(ctx, &state)...)
	if resp.Diagnostics.HasError() {
		return
	}

	genResp, err := r.client.ConvenienceStoreService.GenerateDeleteSAML2ServiceProviderProposal(ctx, connect.NewRequest(&conveniencestorev1.GenerateDeleteSAML2ServiceProviderProposalRequest{
		Base: &conveniencestorev1.GenerateDeleteSAML2ServiceProviderProposalRequest_Base{
			ResourceS2R:   state.ID.ValueString(),
			Justification: destroyJustification("SAML2 SP", state.Name.ValueString(), state.ID.ValueString()),
		},
	}))
	if err != nil {
		resp.Diagnostics.AddError("GenerateDeleteSAML2ServiceProviderProposal", err.Error())

		return
	}

	err = sendAndAwaitDelete(ctx, r.client, r.client.OrgS2R, genResp.Msg.GetInvokeRequest(), 0)
	if err != nil {
		resp.Diagnostics.AddError("Deleting SAML2 SP", err.Error())

		return
	}
}

func (r *saml2ServiceProvider) ImportState(ctx context.Context, req resource.ImportStateRequest, resp *resource.ImportStateResponse) {
	// Import id is the resource_s2r. populateSPModel on Read fills in
	// team_s2r (parsed from the URI) and the typed account block
	// (decoded from the saml2v2 oneof). idp_resource_s2r is left
	// untouched -- the SP<->IdP binding is immutable, so the HCL value
	// supplied at apply is authoritative; a bare import will show a
	// one-time diff against an empty state until HCL is reconciled.
	// org_s2r lives on the provider.
	resource.ImportStatePassthroughID(ctx, path.Root("id"), req, resp)
}

// setAccountOnRequest assigns the per-integration account oneof on the
// request from the plan's account block. Returns the kind string used
// for the account_type computed attribute. The request's account oneof
// reuses the saml2v2 nested per-integration types directly, so each
// branch is a thin wrap.
//
//nolint:cyclop // one branch per account variant; refactoring per-variant helpers would hurt readability.
func setAccountOnRequest(ctx context.Context, base *conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base, plan *saml2ServiceProviderModel) (string, diag.Diagnostics) {
	var diags diag.Diagnostics
	if plan.Account == nil {
		diags.AddError("account is required", "account block must be set with a kind")

		return "", diags
	}
	kind := plan.Account.Kind.ValueString()
	if kind == "" {
		diags.AddError("account.kind is required", "set account.kind to one of: "+strings.Join(spAccountKinds(), ", "))

		return "", diags
	}

	switch kind {
	case kindAWS:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_Aws{Aws: &saml2v2.SAML2ServiceProvider_AWS{
			SamlProviderArn: plan.Account.AWS.SAMLProviderARN.ValueString(),
			AllowedRoleArns: listToStrings(ctx, plan.Account.AWS.AllowedRoleARNs, &diags),
		}}
	case kindCloudflare:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_Cloudflare{Cloudflare: &saml2v2.SAML2ServiceProvider_Cloudflare{
			SsoEndpoint:  plan.Account.Cloudflare.SSOEndpoint.ValueString(),
			DefaultEmail: plan.Account.Cloudflare.DefaultEmail.ValueString(),
		}}
	case kindEventBrite:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_EventBrite{EventBrite: &saml2v2.SAML2ServiceProvider_EventBrite{}}
	case kindGCP:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_Gcp{Gcp: &saml2v2.SAML2ServiceProvider_GCP{
			DefaultEmail: plan.Account.GCP.DefaultEmail.ValueString(),
		}}
	case kindGoogleWorkspace:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_GoogleWorkspace{GoogleWorkspace: &saml2v2.SAML2ServiceProvider_GoogleWorkspace{}}
	case kindGoogleWorkspaceLegacy:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_GoogleWorkspaceLegacy{GoogleWorkspaceLegacy: &saml2v2.SAML2ServiceProvider_GoogleWorkspaceLegacy{
			DefaultEmail: plan.Account.GoogleWorkspaceLegacy.DefaultEmail.ValueString(),
			DomainName:   plan.Account.GoogleWorkspaceLegacy.DomainName.ValueString(),
		}}
	case kindIBMCloud:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_IbmCloud{IbmCloud: &saml2v2.SAML2ServiceProvider_IBMCloud{
			LoginUrl: plan.Account.IBMCloud.LoginURL.ValueString(),
		}}
	case kindKandji:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_Kandji{Kandji: &saml2v2.SAML2ServiceProvider_Kandji{
			DefaultEmail: plan.Account.Kandji.DefaultEmail.ValueString(),
		}}
	case kindMicrosoftEntraID:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_MicrosoftEntraId{MicrosoftEntraId: &saml2v2.SAML2ServiceProvider_MicrosoftEntraID{}}
	case kindOkta:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_Okta{Okta: &saml2v2.SAML2ServiceProvider_Okta{
			AllowedEmails: listToStrings(ctx, plan.Account.Okta.AllowedEmails, &diags),
		}}
	case kindOracleCloud:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_OracleCloud{OracleCloud: &saml2v2.SAML2ServiceProvider_OracleCloud{}}
	case kindPagerDuty:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_PagerDuty{PagerDuty: &saml2v2.SAML2ServiceProvider_PagerDuty{}}
	case kindPitchBook:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_PitchBook{PitchBook: &saml2v2.SAML2ServiceProvider_PitchBook{}}
	case kindRapid7:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_Rapid7{Rapid7: &saml2v2.SAML2ServiceProvider_Rapid7{
			DefaultRelayState: plan.Account.Rapid7.DefaultRelayState.ValueString(),
			DefaultEmail:      plan.Account.Rapid7.DefaultEmail.ValueString(),
			DefaultFirstName:  plan.Account.Rapid7.DefaultFirstName.ValueString(),
			DefaultLastName:   plan.Account.Rapid7.DefaultLastName.ValueString(),
			DefaultRbacGroups: listToStrings(ctx, plan.Account.Rapid7.DefaultRBACGroups, &diags),
		}}
	case kindStripe:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_Stripe{Stripe: &saml2v2.SAML2ServiceProvider_Stripe{
			AccountId: plan.Account.Stripe.AccountID.ValueString(),
		}}
	case kindVeeam:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_Veeam{Veeam: &saml2v2.SAML2ServiceProvider_Veeam{}}
	case kindWorkday:
		base.Account = &conveniencestorev1.GenerateCreateSAML2ServiceProviderProposalRequest_Base_Workday{Workday: &saml2v2.SAML2ServiceProvider_Workday{}}
	default:
		diags.AddError("unknown account variant", kind)

		return "", diags
	}

	return kind, diags
}

// populateSPModel fills state from a fetched record. Decodes the
// v2 SAML2ServiceProvider payload to reconstruct every attribute the
// resource owns, including the typed account block (round-trip of
// the saml2v2 oneof back into HCL sub-blocks). Used by both Create
// and Read so import is plan-idempotent against the record's
// authenticated bytes.
func populateSPModel(ctx context.Context, m *saml2ServiceProviderModel, resourceS2R string, rec *conveniencestorev1.SAML2ResourceRecord, accountType string, diags *diag.Diagnostics) {
	m.ID = types.StringValue(resourceS2R)
	if teamS2R := teamS2RFromResourceS2R(resourceS2R); teamS2R != "" {
		m.TeamS2R = types.StringValue(teamS2R)
	}

	signed := rec.GetContent().GetUpdateableRecord().GetContent().GetSignedServiceProvider()
	if signed == nil {
		//nolint:staticcheck // fallback for legacy top-level record variant
		signed = rec.GetSignedServiceProvider()
	}
	if signed == nil {
		m.AccountType = types.StringValue(accountType)

		return
	}
	var sp saml2v2.SAML2ServiceProvider
	err := proto.Unmarshal(signed.GetAuthenticated(), &sp)
	if err != nil {
		m.AccountType = types.StringValue(accountType)

		return
	}
	// idp_resource_s2r is intentionally not refreshed from the record:
	// the SP<->IdP binding is forceNew/immutable, so the value supplied
	// at create time is authoritative for the lifetime of the SP. The
	// record only carries idp_coord_id_hint (raw IdP id), whose encoding
	// doesn't round-trip cleanly into an s2r URI without the obfuscation
	// helpers. Bare imports leave it empty until the user populates HCL.
	m.Name = types.StringValue(sp.GetName())
	m.Description = types.StringValue(sp.GetDescription())
	m.NotificationPolicy = types.StringValue(notificationPolicyToString(sp.GetNotificationPolicy()))
	m.Sensitivity = types.StringValue(sensitivityLevelToString(sp.GetSensitivity().GetLevel()))
	m.EntityID = types.StringValue(sp.GetMetadata().GetEntityDescriptor().GetEntityId())
	if descs := sp.GetMetadata().GetEntityDescriptor().GetSpSsoDescriptor(); len(descs) > 0 {
		if endpoints := descs[0].GetAssertionConsumerService(); len(endpoints) > 0 {
			m.ACSURL = types.StringValue(endpoints[0].GetBase().GetLocation())
		}
	}

	if account, kind := accountFromSP(ctx, &sp, diags); account != nil {
		m.Account = account
		m.AccountType = types.StringValue(kind)
	} else {
		m.AccountType = types.StringValue(accountType)
	}
}

// accountFromSP rebuilds the typed account block from the SP record's
// authenticated state. Mirrors setAccountOnRequest in reverse: walks
// the saml2v2 oneof, populates the matching sub-block, sets Kind. The
// per-list-variant fields (AWS allowed_role_arns, Okta allowed_emails,
// Rapid7 default_rbac_groups) round-trip via stringsToList. Returns
// (nil, "") for unknown / unset variants so the caller falls back to
// preserving plan-state.
//
//nolint:cyclop // one branch per account variant; collapsing them obscures the round-trip.
func accountFromSP(ctx context.Context, sp *saml2v2.SAML2ServiceProvider, diags *diag.Diagnostics) (*accountModel, string) {
	switch a := sp.GetAccount().(type) {
	case *saml2v2.SAML2ServiceProvider_Aws:
		return &accountModel{
			Kind: types.StringValue(kindAWS),
			AWS: &accountAWSModel{
				SAMLProviderARN: types.StringValue(a.Aws.GetSamlProviderArn()),
				AllowedRoleARNs: stringsToList(ctx, a.Aws.GetAllowedRoleArns(), diags),
			},
		}, kindAWS
	case *saml2v2.SAML2ServiceProvider_Cloudflare_:
		return &accountModel{
			Kind: types.StringValue(kindCloudflare),
			Cloudflare: &accountCloudflareModel{
				SSOEndpoint:  types.StringValue(a.Cloudflare.GetSsoEndpoint()),
				DefaultEmail: types.StringValue(a.Cloudflare.GetDefaultEmail()),
			},
		}, kindCloudflare
	case *saml2v2.SAML2ServiceProvider_EventBrite_:
		return &accountModel{Kind: types.StringValue(kindEventBrite), EventBrite: &accountEventBriteModel{}}, kindEventBrite
	case *saml2v2.SAML2ServiceProvider_Gcp:
		return &accountModel{
			Kind: types.StringValue(kindGCP),
			GCP:  &accountGCPModel{DefaultEmail: types.StringValue(a.Gcp.GetDefaultEmail())},
		}, kindGCP
	case *saml2v2.SAML2ServiceProvider_GoogleWorkspace_:
		return &accountModel{Kind: types.StringValue(kindGoogleWorkspace), GoogleWorkspace: &accountGoogleWorkspaceModel{}}, kindGoogleWorkspace
	case *saml2v2.SAML2ServiceProvider_GoogleWorkspaceLegacy_:
		return &accountModel{
			Kind: types.StringValue(kindGoogleWorkspaceLegacy),
			GoogleWorkspaceLegacy: &accountGoogleWorkspaceLegacyModel{
				DefaultEmail: types.StringValue(a.GoogleWorkspaceLegacy.GetDefaultEmail()),
				DomainName:   types.StringValue(a.GoogleWorkspaceLegacy.GetDomainName()),
			},
		}, kindGoogleWorkspaceLegacy
	case *saml2v2.SAML2ServiceProvider_IbmCloud:
		return &accountModel{
			Kind:     types.StringValue(kindIBMCloud),
			IBMCloud: &accountIBMCloudModel{LoginURL: types.StringValue(a.IbmCloud.GetLoginUrl())},
		}, kindIBMCloud
	case *saml2v2.SAML2ServiceProvider_Kandji_:
		return &accountModel{
			Kind:   types.StringValue(kindKandji),
			Kandji: &accountKandjiModel{DefaultEmail: types.StringValue(a.Kandji.GetDefaultEmail())},
		}, kindKandji
	case *saml2v2.SAML2ServiceProvider_MicrosoftEntraId:
		return &accountModel{Kind: types.StringValue(kindMicrosoftEntraID), MicrosoftEntraID: &accountMicrosoftEntraIDModel{}}, kindMicrosoftEntraID
	case *saml2v2.SAML2ServiceProvider_Okta_:
		return &accountModel{
			Kind: types.StringValue(kindOkta),
			Okta: &accountOktaModel{AllowedEmails: stringsToList(ctx, a.Okta.GetAllowedEmails(), diags)},
		}, kindOkta
	case *saml2v2.SAML2ServiceProvider_OracleCloud_:
		return &accountModel{Kind: types.StringValue(kindOracleCloud), OracleCloud: &accountOracleCloudModel{}}, kindOracleCloud
	case *saml2v2.SAML2ServiceProvider_PagerDuty_:
		return &accountModel{Kind: types.StringValue(kindPagerDuty), PagerDuty: &accountPagerDutyModel{}}, kindPagerDuty
	case *saml2v2.SAML2ServiceProvider_PitchBook_:
		return &accountModel{Kind: types.StringValue(kindPitchBook), PitchBook: &accountPitchBookModel{}}, kindPitchBook
	case *saml2v2.SAML2ServiceProvider_Rapid7_:
		return &accountModel{
			Kind: types.StringValue(kindRapid7),
			Rapid7: &accountRapid7Model{
				DefaultRelayState: types.StringValue(a.Rapid7.GetDefaultRelayState()),
				DefaultEmail:      types.StringValue(a.Rapid7.GetDefaultEmail()),
				DefaultFirstName:  types.StringValue(a.Rapid7.GetDefaultFirstName()),
				DefaultLastName:   types.StringValue(a.Rapid7.GetDefaultLastName()),
				DefaultRBACGroups: stringsToList(ctx, a.Rapid7.GetDefaultRbacGroups(), diags),
			},
		}, kindRapid7
	case *saml2v2.SAML2ServiceProvider_Stripe_:
		return &accountModel{
			Kind:   types.StringValue(kindStripe),
			Stripe: &accountStripeModel{AccountID: types.StringValue(a.Stripe.GetAccountId())},
		}, kindStripe
	case *saml2v2.SAML2ServiceProvider_Veeam_:
		return &accountModel{Kind: types.StringValue(kindVeeam), Veeam: &accountVeeamModel{}}, kindVeeam
	case *saml2v2.SAML2ServiceProvider_Workday_:
		return &accountModel{Kind: types.StringValue(kindWorkday), Workday: &accountWorkdayModel{}}, kindWorkday
	}

	return nil, ""
}

// stringsToList encodes a []string into a types.List for the schema.
// Inverse of listToStrings; appends to diags on encoding error.
func stringsToList(ctx context.Context, src []string, diags *diag.Diagnostics) types.List {
	out, d := types.ListValueFrom(ctx, types.StringType, src)
	diags.Append(d...)

	return out
}

// listToStrings decodes a types.List of string into []string.
func listToStrings(ctx context.Context, l types.List, diags *diag.Diagnostics) []string {
	if l.IsNull() || l.IsUnknown() {
		return nil
	}
	var out []string
	if d := l.ElementsAs(ctx, &out, false); d.HasError() {
		diags.Append(d...)

		return nil
	}

	return out
}
