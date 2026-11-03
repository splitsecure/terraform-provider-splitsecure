// Package provider implements the SplitSecure Terraform provider.
package provider

import (
	"context"
	"os"

	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/provider/schema"
	"github.com/hashicorp/terraform-plugin-framework/resource"
	"github.com/hashicorp/terraform-plugin-framework/types"

	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/authn"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/services/org"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/services/saml2"
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
		Description: "Terraform provider for managing SplitSecure resources. The provider signs in as a service account " +
			"with a registered key: register the public half in the console, then give the provider the account, the key id " +
			"the console shows and the private key.",
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
				Description: "Required. Key id the console assigned when the public key was registered. Falls back to SPLITSECURE_KEY_ID.",
			},
			"private_key": schema.StringAttribute{
				Optional:  true,
				Sensitive: true,
				Description: "Required. PEM private key matching key_id: ECDSA P-256, P-384 or P-521, or Ed25519. RSA keys are refused. " +
					"Falls back to SPLITSECURE_PRIVATE_KEY.",
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

	serviceAccountS2R := valueOrEnv(config.ServiceAccountS2R, "SPLITSECURE_SERVICE_ACCOUNT_S2R")
	keyID := valueOrEnv(config.KeyID, "SPLITSECURE_KEY_ID")
	privateKey := valueOrEnv(config.PrivateKey, "SPLITSECURE_PRIVATE_KEY")
	for name, value := range map[string]string{
		"service_account_s2r": serviceAccountS2R,
		"key_id":              keyID,
		"private_key":         privateKey,
	} {
		if value == "" {
			resp.Diagnostics.AddError("Missing "+name, name+" must be set in the provider config or its SPLITSECURE_ environment variable.")
		}
	}
	if resp.Diagnostics.HasError() {
		return
	}

	key, err := authn.ParseKey(serviceAccountS2R, keyID, []byte(privateKey))
	if err != nil {
		resp.Diagnostics.AddError("Invalid private_key", err.Error())

		return
	}

	c, err := client.New(client.Config{Endpoint: endpoint, OrgS2R: orgS2R, Version: p.version, Key: key})
	if err != nil {
		resp.Diagnostics.AddError("Invalid endpoint", err.Error())

		return
	}
	resp.DataSourceData = c
	resp.ResourceData = c
}

func valueOrEnv(v types.String, env string) string {
	if s := v.ValueString(); s != "" {
		return s
	}

	return os.Getenv(env)
}

func (p *splitsecureProvider) Resources(_ context.Context) []func() resource.Resource {
	return []func() resource.Resource{
		saml2.NewIdentityProvider,
		saml2.NewServiceProvider,
		org.NewGrant,
		org.NewGroup,
	}
}

func (p *splitsecureProvider) DataSources(_ context.Context) []func() datasource.DataSource {
	return []func() datasource.DataSource{
		org.NewOrganizationDataSource,
		org.NewMemberDataSource,
		org.NewPrincipalDataSource,
		org.NewGroupDataSource,
	}
}
