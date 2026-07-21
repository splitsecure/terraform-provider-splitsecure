package org

import (
	"context"
	"errors"
	"fmt"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	orgsvcv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/orgsvc/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

var _ datasource.DataSource = (*groupDataSource)(nil)

var (
	errGroupNotFound      = errors.New("group not found")
	errUnknownGroupSource = errors.New("unknown group source")
	errEmptyGroupResp     = errors.New("server returned an empty group")
)

type groupDataSource struct {
	client *client.Client
}

type groupDataSourceModel struct {
	GroupS2R types.String `tfsdk:"group_s2r"`
	Name     types.String `tfsdk:"name"`
	Source   types.String `tfsdk:"source"`
}

// NewGroupDataSource returns a factory for the splitsecure_group data
// source.
func NewGroupDataSource() datasource.DataSource {
	return &groupDataSource{}
}

func (d *groupDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_group"
}

func (d *groupDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *groupDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Resolves an org group by its stable group_s2r, exposing its current name and source. " +
			"Lookup is by group_s2r only: a group's name is mutable and not unique server-side, so it is not a " +
			"stable key. The system Everyone group is not a regular group; read everyone_group_s2r from the " +
			"splitsecure_organization data source instead.",
		Attributes: map[string]schema.Attribute{
			"group_s2r": schema.StringAttribute{
				Required:    true,
				Description: "Group s2r URI to resolve. Also usable directly as a grant grantee.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"name": schema.StringAttribute{
				Computed:    true,
				Description: "Current group name. Mutable server-side, so do not treat it as an identifier.",
			},
			"source": schema.StringAttribute{
				Computed:    true,
				Description: `Where the group is managed: "local", "scim", or "system".`,
			},
		},
	}
}

func (d *groupDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config groupDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	group := d.getByS2R(ctx, config.GroupS2R.ValueString(), &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	source, err := groupSourceToString(group.GetSource())
	if err != nil {
		resp.Diagnostics.AddError("Decoding group source", err.Error())

		return
	}

	config.Name = types.StringValue(group.GetName())
	config.Source = types.StringValue(source)
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// getByS2R resolves a group directly by its stable s2r.
func (d *groupDataSource) getByS2R(ctx context.Context, groupS2R string, diags *diag.Diagnostics) *orgsvcv1.Group {
	getResp, err := d.client.OrgService.GetGroup(ctx, connect.NewRequest(&orgsvcv1.GetGroupRequest{
		GroupS2R: groupS2R,
	}))
	if err != nil {
		if connect.CodeOf(err) == connect.CodeNotFound {
			diags.AddError("Looking up group", fmt.Sprintf("%s: %s", errGroupNotFound, groupS2R))

			return nil
		}
		diags.AddError("GetGroup", err.Error())

		return nil
	}
	g := getResp.Msg.GetGroup()
	if g.GetGroupS2R() == "" {
		diags.AddError("Looking up group", fmt.Sprintf("%s for %s", errEmptyGroupResp, groupS2R))

		return nil
	}

	return g
}

func groupSourceToString(s orgsvcv1.GroupSource) (string, error) {
	switch s {
	case orgsvcv1.GroupSource_GROUP_SOURCE_LOCAL:
		return "local", nil
	case orgsvcv1.GroupSource_GROUP_SOURCE_SCIM:
		return "scim", nil
	case orgsvcv1.GroupSource_GROUP_SOURCE_SYSTEM:
		return "system", nil
	case orgsvcv1.GroupSource_GROUP_SOURCE_UNSPECIFIED:
		return "", fmt.Errorf("%w: %s", errUnknownGroupSource, s)
	default:
		return "", fmt.Errorf("%w: %s", errUnknownGroupSource, s)
	}
}
