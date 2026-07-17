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

var _ datasource.DataSource = (*principalDataSource)(nil)

var (
	errNoPrincipal        = errors.New("no principal")
	errAmbiguousPrincipal = errors.New("email resolves to multiple principals")
	errBadPrincipalS2R    = errors.New("resolved principal s2r is malformed")
)

type principalDataSource struct {
	client *client.Client
}

type principalDataSourceModel struct {
	Email       types.String `tfsdk:"email"`
	S2R         types.String `tfsdk:"s2r"`
	Kind        types.String `tfsdk:"kind"`
	DisplayName types.String `tfsdk:"display_name"`
}

// NewPrincipalDataSource returns a factory for the splitsecure_principal
// data source.
func NewPrincipalDataSource() datasource.DataSource {
	return &principalDataSource{}
}

func (d *principalDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_principal"
}

func (d *principalDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = clientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *principalDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Resolves an org principal (user or service account) to its s2r by the email shown in the console. " +
			"Use the s2r as a group member or grant grantee.",
		Attributes: map[string]schema.Attribute{
			"email": schema.StringAttribute{
				Required:    true,
				Description: "Email of the principal, copy-pasted from the console. Matched case-insensitively.",
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"s2r": schema.StringAttribute{
				Computed:    true,
				Description: "Principal s2r URI (usr: for users, sa: for service accounts). Usable as a group member or grant grantee.",
			},
			"kind": schema.StringAttribute{
				Computed:    true,
				Description: `Principal kind: "user" or "service_account".`,
			},
			"display_name": schema.StringAttribute{
				Computed:    true,
				Description: "Display name (user) or name (service account).",
			},
		},
	}
}

func (d *principalDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config principalDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)
	if resp.Diagnostics.HasError() {
		return
	}
	email := config.Email.ValueString()

	// GetMembersByEmail resolves users and service accounts alike, server-side —
	// no member roster scan and no client-side service-account parsing.
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

	// One email in, one result out (results are per requested email); its members
	// are the matches for that email.
	results := membersResp.Msg.GetResults()
	var members []*orgsvcv1.Member
	if len(results) > 0 {
		members = results[0].GetMembers()
	}
	switch {
	case len(members) == 0:
		resp.Diagnostics.AddError("Looking up principal", fmt.Sprintf("%s with email %q", errNoPrincipal, email))

		return
	case len(members) > 1:
		resp.Diagnostics.AddError("Looking up principal", fmt.Sprintf("%s: %q -> %d principals", errAmbiguousPrincipal, email, len(members)))

		return
	}

	member := members[0]
	kind, err := principalKindFromS2R(member.GetUserId())
	if err != nil {
		resp.Diagnostics.AddError("Looking up principal", err.Error())

		return
	}

	config.S2R = types.StringValue(member.GetUserId())
	config.Kind = types.StringValue(kind)
	config.DisplayName = types.StringValue(member.GetDisplayName())
	resp.Diagnostics.Append(resp.State.Set(ctx, config)...)
}

// principalKindFromS2R maps the kind segment of a principal s2r
// (s2r:{deployment}:{kind}:{id}) to the data source's kind value.
func principalKindFromS2R(s2r string) (string, error) {
	parts := strings.SplitN(s2r, ":", 4)
	if len(parts) < 4 || parts[0] != "s2r" {
		return "", fmt.Errorf("%w: %q", errBadPrincipalS2R, s2r)
	}
	switch parts[2] {
	case "usr":
		return "user", nil
	case "sa":
		return "service_account", nil
	default:
		return "", fmt.Errorf("%w: %q (unexpected kind %q)", errBadPrincipalS2R, s2r, parts[2])
	}
}
