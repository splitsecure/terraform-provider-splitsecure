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

	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/services/org"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/services/saml2"
)

var _ provider.Provider = (*splitsecureProvider)(nil)

type splitsecureProvider struct {
	version string
}

type splitsecureProviderModel struct {
	BearerToken types.String `tfsdk:"bearer_token"`
	Endpoint    types.String `tfsdk:"endpoint"`
	OrgS2R      types.String `tfsdk:"org_s2r"`
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
		Description: "Terraform provider for managing SplitSecure resources.",
		Attributes: map[string]schema.Attribute{
			"bearer_token": schema.StringAttribute{
				Optional:    true,
				Sensitive:   true,
				Description: "Required. Service account API key token (s2ak_...). Falls back to SPLITSECURE_BEARER_TOKEN environment variable.",
			},
			"endpoint": schema.StringAttribute{
				Optional:    true,
				Description: "SplitSecure API endpoint URL. Can also be set with SPLITSECURE_ENDPOINT. Defaults to production.",
			},
			"org_s2r": schema.StringAttribute{
				Optional: true,
				Description: "Org s2r URI hosting the team(s) that own the resources managed by this provider; the proposal-scoped managed enclave is " +
					"spawned in this org for every Create / Delete. Falls back to SPLITSECURE_ORG_S2R. Multi-org callers alias the provider.",
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

	bearerToken := config.BearerToken.ValueString()
	if bearerToken == "" {
		bearerToken = os.Getenv("SPLITSECURE_BEARER_TOKEN")
	}

	if bearerToken == "" {
		resp.Diagnostics.AddError("Missing bearer token", "bearer_token must be set in the provider config or SPLITSECURE_BEARER_TOKEN environment variable.")

		return
	}

	endpoint := config.Endpoint.ValueString()
	if endpoint == "" {
		endpoint = os.Getenv("SPLITSECURE_ENDPOINT")
	}

	if endpoint == "" {
		endpoint = "https://monolith.us-east-2.aws.splitsecure.com"
	}

	orgS2R := config.OrgS2R.ValueString()
	if orgS2R == "" {
		orgS2R = os.Getenv("SPLITSECURE_ORG_S2R")
	}
	if orgS2R == "" {
		resp.Diagnostics.AddError("Missing org_s2r", "org_s2r must be set in the provider config or SPLITSECURE_ORG_S2R environment variable.")

		return
	}

	c := client.New(endpoint, bearerToken, orgS2R, p.version)
	resp.DataSourceData = c
	resp.ResourceData = c
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
		org.NewGroupDataSource,
	}
}
