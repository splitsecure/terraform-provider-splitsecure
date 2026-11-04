// Package provider implements the SplitSecure Terraform provider.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/authn"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/services/connectedapp"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/services/oidc"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/services/org"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/services/saml2"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/services/vault"
)

var _ provider.Provider = (*splitsecureProvider)(nil)

const defaultEndpoint = "https://monolith.us-east-2.aws.splitsecure.com"

type splitsecureProvider struct {
	version string
}

type splitsecureProviderModel struct {
	Endpoint          types.String `tfsdk:"endpoint"`
	OrgS2R            types.String `tfsdk:"org_s2r"`
	ServiceAccountS2R types.String `tfsdk:"service_account_s2r"`
	KeyID             types.String `tfsdk:"key_id"`
	PrivateKey        types.String `tfsdk:"private_key"`

	WorkloadIdentity *workloadIdentityModel `tfsdk:"workload_identity"`
}

type workloadIdentityModel struct {
	Token types.String `tfsdk:"token"`
}

// New returns a factory function for the SplitSecure provider.
func New(version string) func() provider.Provider {
	return func() provider.Provider {
		return &splitsecureProvider{version: version}
	}
}

func (p *splitsecureProvider) Metadata(_ context.Context, _ provider.MetadataRequest, resp *provider.MetadataResponse) {
	resp.TypeName = "splitsecure"
	resp.Version = p.version
}

func (p *splitsecureProvider) Schema(_ context.Context, _ provider.SchemaRequest, resp *provider.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Terraform provider for managing SplitSecure resources. The provider signs in as a service account, " +
			"either with a registered key (service_account_s2r, key_id and private_key) or with workload identity " +
			"(service_account_s2r and a workload_identity block). Use one, not both.",
		Attributes: map[string]schema.Attribute{
			"endpoint": schema.StringAttribute{
				Optional:    true,
				Description: "SplitSecure API endpoint URL. Can also be set with SPLITSECURE_ENDPOINT. Defaults to production.",
			},
			"org_s2r": schema.StringAttribute{
				Optional: true,
				Description: "Org s2r URI hosting the team(s) that own the resources managed by this provider; the proposal-scoped managed enclave is " +
					"spawned in this org for every Create / Delete. Falls back to SPLITSECURE_ORG_S2R. Multi-org callers alias the provider.",
			},
			"service_account_s2r": schema.StringAttribute{
				Optional:    true,
				Description: "Required. Service account s2r URI (s2r:<deployment>:sa:<id>). Falls back to SPLITSECURE_SERVICE_ACCOUNT_S2R.",
			},
			"key_id": schema.StringAttribute{
				Optional:    true,
				Description: "Required without workload_identity. Key id the console assigned when the public key was registered. Falls back to SPLITSECURE_KEY_ID.",
			},
			"private_key": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "Required without workload_identity. PEM private key matching key_id: ECDSA P-256, P-384 or P-521, or Ed25519. RSA keys are refused. " +
					"Falls back to SPLITSECURE_PRIVATE_KEY.",
			},
		},
		Blocks: map[string]schema.Block{
			"workload_identity": schema.SingleNestedBlock{
				Description: "Sign in with an external OIDC token instead of a key. The service account needs a binding that matches the token. " +
					"Leave the block empty inside GitHub Actions to use the job's ID token, which needs the id-token: write permission.",
				Attributes: map[string]schema.Attribute{
					"token": schema.StringAttribute{
						Optional:  true,
						Sensitive: true,
						Description: "External OIDC token. Its aud claim must be the endpoint's origin. Falls back to SPLITSECURE_WORKLOAD_TOKEN. " +
							"When unset, the GitHub Actions ID token is requested on every refresh.",
					},
				},
			},
		},
	}
}

func (p *splitsecureProvider) Configure(ctx context.Context, req provider.ConfigureRequest, resp *provider.ConfigureResponse) {
	var config splitsecureProviderModel

	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)

	if resp.Diagnostics.HasError() {
		return
	}

	endpoint := valueOrEnv(config.Endpoint, "SPLITSECURE_ENDPOINT")
	if endpoint == "" {
		endpoint = defaultEndpoint
	}

	orgS2R := valueOrEnv(config.OrgS2R, "SPLITSECURE_ORG_S2R")
	if orgS2R == "" {
		resp.Diagnostics.AddError("Missing org_s2r", "org_s2r must be set in the provider config or SPLITSECURE_ORG_S2R environment variable.")

		return
	}

	cfg := client.Config{Endpoint: endpoint, OrgS2R: orgS2R, Version: p.version}
	if !p.configureCredential(&config, &cfg, &resp.Diagnostics) {
		return
	}

	c, err := client.New(cfg)
	if err != nil {
		resp.Diagnostics.AddError("Invalid endpoint", err.Error())

		return
	}
	resp.DataSourceData = c
	resp.ResourceData = c
}

func (p *splitsecureProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		saml2.NewIdentityProviderResource,
		oidc.NewIssuerResource,
		vault.NewFolderResource,
		vault.NewGrantResource,
		vault.NewNodeGrantsResource,
		connectedapp.NewConnectedAppResource,
		org.NewGrant,
		org.NewGroup,
		org.NewGroupMember,
	}
}

func (p *splitsecureProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		vault.NewVaultDataSource,
		org.NewOrganizationDataSource,
		org.NewMemberDataSource,
		org.NewPrincipalDataSource,
		org.NewGroupDataSource,
	}
}

// configureCredential fills the key or the workload identity of cfg, and
// reports whether it succeeded.
func (p *splitsecureProvider) configureCredential(config *splitsecureProviderModel, cfg *client.Config, diags *diag.Diagnostics) bool {
	serviceAccountS2R := valueOrEnv(config.ServiceAccountS2R, "SPLITSECURE_SERVICE_ACCOUNT_S2R")
	keyID := valueOrEnv(config.KeyID, "SPLITSECURE_KEY_ID")
	privateKey := valueOrEnv(config.PrivateKey, "SPLITSECURE_PRIVATE_KEY")

	if serviceAccountS2R == "" {
		diags.AddError("Missing service_account_s2r", "service_account_s2r must be set in the provider config or SPLITSECURE_SERVICE_ACCOUNT_S2R environment variable.")

		return false
	}

	if config.WorkloadIdentity != nil {
		if keyID != "" || privateKey != "" {
			diags.AddError("Conflicting credentials", "Set either the workload_identity block or key_id and private_key, not both.")

			return false
		}

		return p.configureWorkload(config.WorkloadIdentity, serviceAccountS2R, cfg, diags)
	}

	for name, value := range map[string]string{"key_id": keyID, "private_key": privateKey} {
		if value == "" {
			diags.AddError("Missing "+name, name+" must be set in the provider config or its SPLITSECURE_ environment variable, or set the workload_identity block instead.")
		}
	}
	if diags.HasError() {
		return false
	}

	key, err := authn.ParseKey(serviceAccountS2R, keyID, []byte(privateKey))
	if err != nil {
		diags.AddError("Invalid private_key", err.Error())

		return false
	}
	cfg.Key = key

	return true
}

func (p *splitsecureProvider) configureWorkload(block *workloadIdentityModel, serviceAccountS2R string, cfg *client.Config, diags *diag.Diagnostics) bool {
	var source authn.TokenSource
	if token := valueOrEnv(block.Token, "SPLITSECURE_WORKLOAD_TOKEN"); token != "" {
		source = func(context.Context, string) (string, error) { return token, nil }
	} else {
		var err error
		source, err = authn.GitHubActionsTokenSource(nil)
		if err != nil {
			diags.AddError("No workload identity token", "Set workload_identity.token or SPLITSECURE_WORKLOAD_TOKEN, or run inside GitHub Actions. "+err.Error())

			return false
		}
	}
	cfg.Workload = &authn.Workload{ServiceAccountS2R: serviceAccountS2R, TokenSource: source}

	return true
}

func valueOrEnv(v types.String, env string) string {
	if s := v.ValueString(); s != "" {
		return s
	}

	return os.Getenv(env)
}
