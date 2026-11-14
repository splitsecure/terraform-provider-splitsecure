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
	"github.com/hashicorp/terraform-plugin-framework/path"
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
	errAmbiguousGroup     = errors.New("more than one group matches")
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
		Description: "Resolves an org group by its group_s2r or by its name. Set exactly one of them. A name lookup errors when no group or more than one group has the name; " +
			"set source to tell apart groups that share a name. A name is mutable, so prefer group_s2r for a stable key. " +
			"The system Everyone group is not a regular group; read everyone_group_s2r from the splitsecure_organization data source instead.",
		Attributes: map[string]schema.Attribute{
			"group_s2r": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Group s2r URI. Set it to look the group up by s2r, or read it after a lookup by name. Also usable directly as a grant grantee.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					stringvalidator.ExactlyOneOf(path.MatchRoot("name")),
				},
			},
			"name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Group name. Set it to look the group up by exact name in the provider's org. Mutable server-side, so do not treat it as an identifier.",
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"source": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: `Where the group is managed: "local", "scim", or "system". Set it to "local" or "scim" to narrow a lookup by name. A lookup by name never returns a system group.`,
				Validators: []validator.String{
					stringvalidator.OneOf("local", "scim"),
					stringvalidator.ConflictsWith(path.MatchRoot("group_s2r")),
				},
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

	group := d.lookup(ctx, &config, &resp.Diagnostics)
	if resp.Diagnostics.HasError() {
		return
	}

	source, err := groupSourceToString(group.GetSource())
	if err != nil {
		resp.Diagnostics.AddError("Decoding group source", err.Error())

		return
	}

	config.GroupS2R = types.StringValue(group.GetGroupS2R())
	config.Name = types.StringValue(group.GetName())
	config.Source = types.StringValue(source)
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// lookup resolves the group by s2r when it is set and by name otherwise.
func (d *groupDataSource) lookup(ctx context.Context, config *groupDataSourceModel, diags *diag.Diagnostics) *orgsvcv1.Group {
	if !config.GroupS2R.IsNull() && !config.GroupS2R.IsUnknown() {
		return d.getByS2R(ctx, config.GroupS2R.ValueString(), diags)
	}

	group, err := d.findByName(ctx, config.Name.ValueString(), config.Source.ValueString())
	if err != nil {
		diags.AddError("Looking up group", fmt.Sprintf("name %q: %s", config.Name.ValueString(), err))

		return nil
	}

	return group
}

// findByName pages through the org's groups for an exact name, narrowed by source when it is set, and errors unless exactly one matches.
func (d *groupDataSource) findByName(ctx context.Context, name, source string) (*orgsvcv1.Group, error) {
	var (
		match  *orgsvcv1.Group
		cursor []byte
	)

	for {
		resp, err := d.client.OrgService.ListGroups(ctx, connect.NewRequest(&orgsvcv1.ListGroupsRequest{
			OrgS2R: d.client.OrgS2R,
			Page:   pageAfter(cursor),
		}))
		if err != nil {
			return nil, fmt.Errorf("listing groups: %w", err)
		}

		for _, g := range resp.Msg.GetGroups() {
			if g.GetName() != name || !sourceMatches(g.GetSource(), source) {
				continue
			}

			if match != nil {
				return nil, errAmbiguousGroup
			}

			match = g
		}

		cursor = resp.Msg.GetNextCursor()
		if len(cursor) == 0 {
			break
		}
	}

	if match == nil {
		return nil, errGroupNotFound
	}

	return match, nil
}

func sourceMatches(s orgsvcv1.GroupSource, want string) bool {
	if want == "" {
		return s != orgsvcv1.GroupSource_GROUP_SOURCE_SYSTEM
	}

	got, err := groupSourceToString(s)

	return err == nil && got == want
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
