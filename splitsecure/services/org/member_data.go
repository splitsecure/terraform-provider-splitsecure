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

var _ datasource.DataSource = (*memberDataSource)(nil)

var (
	errNoOrgMember          = errors.New("no org member")
	errAmbiguousMemberEmail = errors.New("ambiguous member email")
)

type memberDataSource struct {
	client *client.Client
}

type memberDataSourceModel struct {
	Email       types.String `tfsdk:"email"`
	UserS2R     types.String `tfsdk:"user_s2r"`
	DisplayName types.String `tfsdk:"display_name"`
}

// NewMemberDataSource returns a factory for the splitsecure_org_member
// data source.
func NewMemberDataSource() datasource.DataSource {
	return &memberDataSource{}
}

func (d *memberDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_org_member"
}

func (d *memberDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
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

func (d *memberDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Looks up a single org member by email (case-insensitive). Errors if no member or more than one member matches.",
		Attributes: map[string]schema.Attribute{
			"email": schema.StringAttribute{
				Required:    true,
				Description: "Email address of the member to look up. Matched case-insensitively.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
				},
			},
			"user_s2r": schema.StringAttribute{
				Computed:    true,
				Description: "User s2r URI of the member. Usable as a grant grantee or a group member principal.",
			},
			"display_name": schema.StringAttribute{
				Computed:    true,
				Description: "Human-readable display name of the member.",
			},
		},
	}
}

func (d *memberDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config memberDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}

	listResp, err := d.client.OrgService.ListMembers(ctx, connect.NewRequest(&orgsvcv1.ListMembersRequest{
		Base: &orgsvcv1.ListMembersRequest_Base{OrganizationId: d.client.OrgS2R},
	}))
	if err != nil {
		resp.Diagnostics.AddError("ListMembers", err.Error())

		return
	}

	member, err := matchMemberByEmail(listResp.Msg.GetMembers(), config.Email.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Looking up org member", err.Error())

		return
	}

	config.UserS2R = types.StringValue(member.GetUserId())
	config.DisplayName = types.StringValue(member.GetDisplayName())
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// matchMemberByEmail returns the single member whose email equals the
// given email case-insensitively. Zero or multiple matches are errors.
func matchMemberByEmail(members []*orgsvcv1.Member, email string) (*orgsvcv1.Member, error) {
	var matches []*orgsvcv1.Member
	for _, m := range members {
		if strings.EqualFold(m.GetEmail(), email) {
			matches = append(matches, m)
		}
	}

	switch len(matches) {
	case 0:
		return nil, fmt.Errorf("%w with email %q", errNoOrgMember, email)
	case 1:
		return matches[0], nil
	default:
		ids := make([]string, len(matches))
		for i, m := range matches {
			ids[i] = m.GetUserId()
		}

		return nil, fmt.Errorf("%w: %q matches %d members: %s", errAmbiguousMemberEmail, email, len(matches), strings.Join(ids, ", "))
	}
}
