package org

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/types"

	orgsvcv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/orgsvc/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

var _ datasource.DataSource = (*organizationDataSource)(nil)

var errEmptyOrganization = errors.New("GetOrganization returned an empty organization")

type organizationDataSource struct {
	client *client.Client
}

type organizationDataSourceModel struct {
	ID               types.String `tfsdk:"id"`
	Name             types.String `tfsdk:"name"`
	EveryoneGroupS2R types.String `tfsdk:"everyone_group_s2r"`
}

// NewOrganizationDataSource returns a factory for the
// splitsecure_organization data source.
func NewOrganizationDataSource() datasource.DataSource {
	return &organizationDataSource{}
}

func (d *organizationDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_organization"
}

func (d *organizationDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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
	d.client = c
}

func (d *organizationDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "The organization the provider is configured against. Takes no arguments; the org comes from the provider's org_s2r.",
		Attributes: map[string]schema.Attribute{
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Org s2r URI.",
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Description: "Human-readable organization name.",
			},
			"everyone_group_s2r": schema.StringAttribute{
				Computed: true,
				Description: "S2R of the org's system Everyone group -- the grantee to use for org-wide grants. " +
					"System groups are NOT returned by group listings (including the splitsecure_group data source); " +
					"this attribute is the way to obtain it.",
			},
		},
	}
}

func (d *organizationDataSource) Read(ctx context.Context, _ datasource.ReadRequest, resp *datasource.ReadResponse) {
	getResp, err := d.client.OrgService.GetOrganization(ctx, connect.NewRequest(&orgsvcv1.GetOrganizationRequest{
		Base: &orgsvcv1.GetOrganizationRequest_Base{OrganizationId: d.client.OrgS2R},
	}))
	if err != nil {
		resp.Diagnostics.AddError("GetOrganization", err.Error())

		return
	}

	o := getResp.Msg.GetOrganization()
	if o == nil {
		resp.Diagnostics.AddError("Reading organization", fmt.Errorf("%w for %s", errEmptyOrganization, d.client.OrgS2R).Error())

		return
	}

	state := organizationDataSourceModel{
		ID:               types.StringValue(o.GetId()),
		Name:             types.StringValue(o.GetName()),
		EveryoneGroupS2R: types.StringValue(o.GetEveryoneGroupS2R()),
	}
	resp.Diagnostics.Append(resp.State.Set(ctx, &state)...)
}
