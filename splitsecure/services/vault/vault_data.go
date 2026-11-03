// Package vault implements the SplitSecure vault data source.
package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/datasource"
	"github.com/hashicorp/terraform-plugin-framework/datasource/schema"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	pagev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/page/v1"
	vaultcatalogv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultcatalog/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultres"
)

var _ datasource.DataSource = (*vaultDataSource)(nil)

const listVaultsPageSize = 100

var (
	errVaultNotFound = errors.New("no vault matches")
	errVaultAmbig    = errors.New("more than one vault matches")
)

type vaultDataSource struct {
	client *client.Client
}

type vaultDataSourceModel struct {
	ID           types.String `tfsdk:"id"`
	Label        types.String `tfsdk:"label"`
	OrgS2R       types.String `tfsdk:"org_s2r"`
	CustodyClass types.String `tfsdk:"custody_class"`
	Status       types.String `tfsdk:"status"`
	TeamIDs      types.List   `tfsdk:"team_ids"`
}

// NewVaultDataSource returns a factory for the splitsecure_vault data source.
func NewVaultDataSource() datasource.DataSource {
	return &vaultDataSource{}
}

func (d *vaultDataSource) Metadata(_ context.Context, req datasource.MetadataRequest, resp *datasource.MetadataResponse) {
	resp.TypeName = req.ProviderTypeName + "_vault"
}

func (d *vaultDataSource) Configure(_ context.Context, req datasource.ConfigureRequest, resp *datasource.ConfigureResponse) {
	d.client = vaultres.ClientFromProviderData(req.ProviderData, &resp.Diagnostics)
}

func (d *vaultDataSource) Schema(_ context.Context, _ datasource.SchemaRequest, resp *datasource.SchemaResponse) {
	resp.Schema = schema.Schema{
		Description: "Resolves a vault by its label. The lookup errors when no vault or more than one vault has the label.",
		Attributes: map[string]schema.Attribute{
			"label": schema.StringAttribute{
				Required:    true,
				Description: "Label of the vault to resolve.",
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
			},
			"org_s2r": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Org s2r URI to search. Defaults to the provider's org_s2r.",
			},
			"id": schema.StringAttribute{
				Computed:    true,
				Description: "Vault id. Use it as the vault_id of vault resources.",
			},
			"custody_class": schema.StringAttribute{
				Computed:    true,
				Description: `Custody class of the vault: "threshold", "online" or "blind".`,
			},
			"status": schema.StringAttribute{
				Computed:    true,
				Description: `Status of the vault: "active" or "sealed".`,
			},
			"team_ids": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Base64-encoded ids of the teams that hold the vault.",
			},
		},
	}
}

func (d *vaultDataSource) Read(ctx context.Context, req datasource.ReadRequest, resp *datasource.ReadResponse) {
	var config vaultDataSourceModel
	resp.Diagnostics.Append(req.Config.Get(ctx, &config)...)

	if resp.Diagnostics.HasError() {
		return
	}

	orgS2R := config.OrgS2R.ValueString()
	if orgS2R == "" {
		orgS2R = d.client.OrgS2R
	}

	label := config.Label.ValueString()

	match, err := d.findByLabel(ctx, orgS2R, label)
	if err != nil {
		resp.Diagnostics.AddError("Resolving vault", fmt.Sprintf("label %q: %s", label, err))

		return
	}

	teamIDs := make([]string, 0, len(match.GetTeamIds()))
	for _, id := range match.GetTeamIds() {
		teamIDs = append(teamIDs, base64.StdEncoding.EncodeToString(id))
	}

	teamIDList, diags := types.ListValueFrom(ctx, types.StringType, teamIDs)
	resp.Diagnostics.Append(diags...)

	if resp.Diagnostics.HasError() {
		return
	}

	config.ID = types.StringValue(match.GetVaultId())
	config.OrgS2R = types.StringValue(orgS2R)
	config.CustodyClass = types.StringValue(strings.ToLower(strings.TrimPrefix(match.GetCustodyClass().String(), "CUSTODY_CLASS_")))
	config.Status = types.StringValue(strings.ToLower(strings.TrimPrefix(match.GetStatus().String(), "VAULT_STATUS_")))
	config.TeamIDs = teamIDList

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

func (d *vaultDataSource) findByLabel(ctx context.Context, orgS2R, label string) (*vaultcatalogv1.VaultSummary, error) {
	var (
		match  *vaultcatalogv1.VaultSummary
		cursor []byte
	)

	for {
		page := &pagev1.PageParams{Limit: listVaultsPageSize}
		if cursor != nil {
			page.DirectionOrCursor = &pagev1.PageParams_DirectionOrCursor{
				Union: &pagev1.PageParams_DirectionOrCursor_Cursor{Cursor: cursor},
			}
		}

		resp, err := d.client.VaultCatalog.ListVaults(ctx, connect.NewRequest(&vaultcatalogv1.ListVaultsRequest{
			Base: &vaultcatalogv1.ListVaultsRequest_Base{OrgS2R: orgS2R, Page: page},
		}))
		if err != nil {
			return nil, fmt.Errorf("listing vaults: %w", err)
		}

		for _, v := range resp.Msg.GetVaults() {
			if v.GetLabel() != label {
				continue
			}

			if match != nil {
				return nil, errVaultAmbig
			}

			match = v
		}

		cursor = resp.Msg.GetNextCursor()
		if len(cursor) == 0 {
			break
		}
	}

	if match == nil {
		return nil, errVaultNotFound
	}

	return match, nil
}
