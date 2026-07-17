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
	errEmptyMemberUserID    = errors.New("member resolved to an empty user_s2r")
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
	d.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
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

	email := config.Email.ValueString()
	membersResp, err := d.client.OrgService.GetMembersByEmail(ctx, connect.NewRequest(&orgsvcv1.GetMembersByEmailRequest{
		Base: &orgsvcv1.GetMembersByEmailRequest_Base{
			OrganizationId: d.client.OrgS2R,
			Emails:         []string{email},
		},
	}))
	if err != nil {
		resp.Diagnostics.AddError("GetMembersByEmail", err.Error())

		return
	}

	member, err := singleMember(membersResp.Msg.GetResults(), email)
	if err != nil {
		resp.Diagnostics.AddError("Looking up org member", err.Error())

		return
	}
	if member.GetUserId() == "" {
		resp.Diagnostics.AddError("Looking up org member", fmt.Sprintf("%s: %s", errEmptyMemberUserID, email))

		return
	}

	config.UserS2R = types.StringValue(member.GetUserId())
	config.DisplayName = types.StringValue(member.GetDisplayName())
	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// singleMember extracts the one member the server resolved for email. The RPC
// returns one Result per requested email (in request order) with the matching
// already done server-side; here zero members means no such member and multiple
// means the address is ambiguous — both errors.
func singleMember(results []*orgsvcv1.GetMembersByEmailResponse_Result, email string) (*orgsvcv1.Member, error) {
	var members []*orgsvcv1.Member
	for _, r := range results {
		if r.GetEmail() == email {
			members = r.GetMembers()

			break
		}
	}

	switch len(members) {
	case 0:
		return nil, fmt.Errorf("%w with email %q", errNoOrgMember, email)
	case 1:
		return members[0], nil
	default:
		ids := make([]string, len(members))
		for i, m := range members {
			ids[i] = m.GetUserId()
		}

		return nil, fmt.Errorf("%w: %q matches %d members: %s", errAmbiguousMemberEmail, email, len(members), strings.Join(ids, ", "))
	}
}
