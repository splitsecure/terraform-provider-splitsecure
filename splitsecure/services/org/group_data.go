package org

import (
	"context"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	orgsvcv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/orgsvc/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

var _ datasource.DataSource = (*groupDataSource)(nil)

var (
	errGroupNotFound      = errors.New("group not found")
	errAmbiguousGroupName = errors.New("ambiguous group name")
	errUnknownGroupSource = errors.New("unknown group source")
)

type groupDataSource struct {
	client *client.Client
}

type groupDataSourceModel struct {
	Name     types.String `tfsdk:"name"`
	GroupS2R types.String `tfsdk:"group_s2r"`
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

func (d *groupDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Looks up a single org group by exact name. Errors if no group or more than one group matches " +
			"(org group names are not unique server-side). The system Everyone group is not listed; " +
			"read everyone_group_s2r from the splitsecure_organization data source instead.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Required:    true,
				Description: "Group name to look up. Matched exactly (case-sensitive).",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"group_s2r": schema.StringAttribute{
				Computed:    true,
				Description: "Group s2r URI. Usable as a grant grantee.",
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

	listResp, err := d.client.OrgService.ListGroups(ctx, connect.NewRequest(&orgsvcv1.ListGroupsRequest{
		OrgS2R: d.client.OrgS2R,
	}))
	if err != nil {
		resp.Diagnostics.AddError("ListGroups", err.Error())

		return
	}

	group, err := matchGroupByName(listResp.Msg.GetGroups(), config.Name.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Looking up group", err.Error())

		return
	}

	source, err := groupSourceToString(group.GetSource())
	if err != nil {
		resp.Diagnostics.AddError("Decoding group source", err.Error())

		return
	}

	config.GroupS2R = types.StringValue(group.GetGroupS2R())
	config.Source = types.StringValue(source)
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// matchGroupByName returns the single group whose name equals the given
// name exactly (case-sensitive). Zero or multiple matches are errors.
func matchGroupByName(groups []*orgsvcv1.Group, name string) (*orgsvcv1.Group, error) {
	var matches []*orgsvcv1.Group
	for _, g := range groups {
		if g.GetName() == name {
			matches = append(matches, g)
		}
	}

	switch len(matches) {
	case 0:
		return nil, fmt.Errorf(
			"%w: no group named %q; note the system Everyone group is not returned by group listings -- "+
				"read everyone_group_s2r from the splitsecure_organization data source instead",
			errGroupNotFound, name)
	case 1:
		return matches[0], nil
	default:
		s2rs := make([]string, len(matches))
		for i, g := range matches {
			s2rs[i] = g.GetGroupS2R()
		}

		return nil, fmt.Errorf("%w: %q matches %d groups (org group names are not unique): %s",
			errAmbiguousGroupName, name, len(matches), strings.Join(s2rs, ", "))
	}
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
