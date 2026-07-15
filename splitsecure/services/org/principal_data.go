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
	errNoPrincipal     = errors.New("no principal")
	errBadOrgS2R       = errors.New("provider org_s2r is not a valid s2r")
	errSAEmailMismatch = errors.New("resolved service account email does not match")
)

// serviceAccountEmailMarker distinguishes a service-account email
// (<sa-id>@<org-id>.serviceaccount.<deployment>.splitsecure.com) from a
// human user email. The local part is the SA's sa: s2r id, so an SA email
// resolves to its s2r by parsing — no directory lookup.
const serviceAccountEmailMarker = ".serviceaccount."

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
			"User emails resolve via the member directory; service-account emails parse directly to their sa: s2r. " +
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

	// A service-account email carries the sa: s2r id in its local part, so
	// it resolves without a directory lookup; anything else is a user email.
	if _, domain, ok := strings.Cut(email, "@"); ok && strings.Contains(domain, serviceAccountEmailMarker) {
		d.resolveServiceAccount(ctx, &config, resp)

		return
	}
	d.resolveUser(ctx, &config, resp)
}

func (d *principalDataSource) resolveUser(ctx context.Context, config *principalDataSourceModel, resp *datasource.ReadResponse) {
	listResp, err := d.client.OrgService.ListMembers(ctx, connect.NewRequest(&orgsvcv1.ListMembersRequest{
		Base: &orgsvcv1.ListMembersRequest_Base{OrganizationId: d.client.OrgS2R},
	}))
	if err != nil {
		resp.Diagnostics.AddError("ListMembers", err.Error())

		return
	}

	member, err := matchMemberByEmail(listResp.Msg.GetMembers(), config.Email.ValueString())
	if err != nil {
		resp.Diagnostics.AddError("Looking up principal", err.Error())

		return
	}

	config.S2R = types.StringValue(member.GetUserId())
	config.Kind = types.StringValue("user")
	config.DisplayName = types.StringValue(member.GetDisplayName())
	resp.Diagnostics.Append(resp.State.Set(ctx, config)...)
}

func (d *principalDataSource) resolveServiceAccount(ctx context.Context, config *principalDataSourceModel, resp *datasource.ReadResponse) {
	deployment, err := deploymentFromS2R(d.client.OrgS2R)
	if err != nil {
		resp.Diagnostics.AddError("Looking up principal", err.Error())

		return
	}
	email := config.Email.ValueString()
	localPart, _, _ := strings.Cut(email, "@")
	saS2R := fmt.Sprintf("s2r:%s:sa:%s", deployment, localPart)

	// Confirm the parsed s2r is a real SA in this org and its email matches
	// what was pasted — guards against a typo pointing at another SA.
	getResp, err := d.client.OrgService.GetServiceAccounts(ctx, connect.NewRequest(&orgsvcv1.GetServiceAccountsRequest{
		Base: &orgsvcv1.GetServiceAccountsRequest_Base{
			OrganizationId:    d.client.OrgS2R,
			ServiceAccountIds: []string{saS2R},
		},
	}))
	if err != nil {
		resp.Diagnostics.AddError("GetServiceAccounts", err.Error())

		return
	}
	sas := getResp.Msg.GetServiceAccounts()
	if len(sas) == 0 {
		resp.Diagnostics.AddError("Looking up principal", fmt.Sprintf("%s with email %q", errNoPrincipal, email))

		return
	}
	sa := sas[0]
	if !strings.EqualFold(sa.GetEmail(), email) {
		resp.Diagnostics.AddError("Looking up principal", fmt.Sprintf("%s: %q -> %q (%s)", errSAEmailMismatch, email, sa.GetEmail(), sa.GetId()))

		return
	}

	config.S2R = types.StringValue(sa.GetId())
	config.Kind = types.StringValue("service_account")
	config.DisplayName = types.StringValue(sa.GetName())
	resp.Diagnostics.Append(resp.State.Set(ctx, config)...)
}

// deploymentFromS2R extracts the deployment segment from an s2r URI
// (s2r:{deployment}:{kind}:{id}).
func deploymentFromS2R(s2r string) (string, error) {
	parts := strings.SplitN(s2r, ":", 4)
	if len(parts) < 4 || parts[0] != "s2r" || parts[1] == "" {
		return "", fmt.Errorf("%w: %q", errBadOrgS2R, s2r)
	}

	return parts[1], nil
}
