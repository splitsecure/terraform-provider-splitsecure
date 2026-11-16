// Package vault implements the SplitSecure vault data source and the vault folder and grant resources.
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
	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/path"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
	"github.com/hashicorp/terraform-plugin-framework/types"

	pagev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/page/v1"
	vaultbrowsev1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1"
	vaultcatalogv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultcatalog/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultres"
)

var _ datasource.DataSource = (*vaultDataSource)(nil)

const listPageSize = 100

var (
	errVaultNotFound = errors.New("no vault matches")
	errVaultAmbig    = errors.New("more than one vault matches")
)

type vaultDataSource struct {
	client *client.Client
}

type vaultDataSourceModel struct {
	ID           types.String `tfsdk:"id"`
	Name         types.String `tfsdk:"name"`
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
		Description: "Resolves a vault by name or by id. Set exactly one of them. A name lookup errors when no vault or more than one vault has the name. " +
			"A name lookup finds vaults the caller is a member of, then vaults reached through shared nodes.",
		Attributes: map[string]schema.Attribute{
			"name": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Name of the vault to resolve. Set exactly one of name and id.",
				Validators: []validator.String{
					stringvalidator.LengthAtLeast(1),
					stringvalidator.ExactlyOneOf(path.MatchRoot("id")),
				},
			},
			"org_s2r": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Org s2r URI to search. Defaults to the provider's org_s2r. It applies to name lookups only. An id lookup ignores it and reports it as set here.",
			},
			"id": schema.StringAttribute{
				Optional:    true,
				Computed:    true,
				Description: "Vault id. Use it as the vault_id of vault resources. Set exactly one of name and id.",
				Validators:  []validator.String{stringvalidator.LengthAtLeast(1)},
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
				Description: "Base64-encoded ids of the teams that hold the vault. Null for an id lookup and for a vault found only through shared nodes.",
			},
		},
	}
}

// vaultMatch is a vault the lookup resolved. A name match carries Summary, or only the id and name when the vault is reachable through shared nodes alone.
// An id match, and a shared-only match once described, carries Described.
type vaultMatch struct {
	VaultID   string
	Name      string
	Summary   *vaultcatalogv1.VaultSummary
	Described *vaultbrowsev1.DescribeVaultResponse
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

	match, err := d.lookup(ctx, orgS2R, &config)
	if err != nil {
		resp.Diagnostics.AddError("Resolving vault", err.Error())

		return
	}

	config.ID = types.StringValue(match.VaultID)
	config.Name = types.StringValue(match.Name)
	config.OrgS2R = types.StringValue(orgS2R)
	config.CustodyClass = types.StringNull()
	config.Status = types.StringNull()
	config.TeamIDs = types.ListNull(types.StringType)

	resp.Diagnostics.Append(applyMatch(ctx, &config, match)...)

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// findByName looks in the caller's member vaults, then in shared nodes, and errors unless exactly one vault matches.
func (d *vaultDataSource) findByName(ctx context.Context, orgS2R, name string) (*vaultMatch, error) {
	var found *vaultMatch

	record := func(m *vaultMatch) error {
		if found != nil && found.VaultID != m.VaultID {
			return errVaultAmbig
		}

		if found == nil {
			found = m
		}

		return nil
	}

	err := d.eachVault(ctx, orgS2R, func(v *vaultcatalogv1.VaultSummary) error {
		if v.GetLabel() != name {
			return nil
		}

		return record(&vaultMatch{VaultID: v.GetVaultId(), Name: v.GetLabel(), Summary: v})
	})
	if err != nil {
		return nil, err
	}

	err = d.eachShared(ctx, orgS2R, func(n *vaultcatalogv1.SharedNode) error {
		if n.GetVaultLabel() != name {
			return nil
		}

		return record(&vaultMatch{VaultID: n.GetVaultId(), Name: n.GetVaultLabel()})
	})
	if err != nil {
		return nil, err
	}

	if found == nil {
		return nil, errVaultNotFound
	}

	return found, nil
}

func (d *vaultDataSource) eachVault(ctx context.Context, orgS2R string, visit func(*vaultcatalogv1.VaultSummary) error) error {
	var cursor []byte

	for {
		resp, err := d.client.VaultCatalog.ListVaults(ctx, connect.NewRequest(&vaultcatalogv1.ListVaultsRequest{
			Base: &vaultcatalogv1.ListVaultsRequest_Base{OrgS2R: orgS2R, Page: pageAt(cursor)},
		}))
		if err != nil {
			return fmt.Errorf("listing vaults: %w", err)
		}

		for _, v := range resp.Msg.GetVaults() {
			err = visit(v)
			if err != nil {
				return err
			}
		}

		cursor = resp.Msg.GetNextCursor()
		if len(cursor) == 0 {
			return nil
		}
	}
}

func (d *vaultDataSource) eachShared(ctx context.Context, orgS2R string, visit func(*vaultcatalogv1.SharedNode) error) error {
	var cursor []byte

	for {
		resp, err := d.client.VaultCatalog.ListSharedWithMe(ctx, connect.NewRequest(&vaultcatalogv1.ListSharedWithMeRequest{
			Base: &vaultcatalogv1.ListSharedWithMeRequest_Base{OrgS2R: orgS2R, Page: pageAt(cursor)},
		}))
		if err != nil {
			return fmt.Errorf("listing shared nodes: %w", err)
		}

		for _, n := range resp.Msg.GetSharedNodes() {
			err = visit(n)
			if err != nil {
				return err
			}
		}

		cursor = resp.Msg.GetNextCursor()
		if len(cursor) == 0 {
			return nil
		}
	}
}

func pageAt(cursor []byte) *pagev1.PageParams {
	page := &pagev1.PageParams{Limit: listPageSize}
	if cursor != nil {
		page.DirectionOrCursor = &pagev1.PageParams_DirectionOrCursor{
			Union: &pagev1.PageParams_DirectionOrCursor_Cursor{Cursor: cursor},
		}
	}

	return page
}

func applySummary(ctx context.Context, m *vaultDataSourceModel, v *vaultcatalogv1.VaultSummary) diag.Diagnostics {
	m.CustodyClass = types.StringValue(enumName(v.GetCustodyClass().String(), "CUSTODY_CLASS_"))
	m.Status = types.StringValue(enumName(v.GetStatus().String(), "VAULT_STATUS_"))

	teamIDs := make([]string, 0, len(v.GetTeamIds()))
	for _, id := range v.GetTeamIds() {
		teamIDs = append(teamIDs, base64.StdEncoding.EncodeToString(id))
	}

	var diags diag.Diagnostics

	m.TeamIDs, diags = types.ListValueFrom(ctx, types.StringType, teamIDs)

	return diags
}

func enumName(name, prefix string) string {
	return strings.ToLower(strings.TrimPrefix(name, prefix))
}

// lookup resolves the vault by id when it is set and by name otherwise.
func (d *vaultDataSource) lookup(ctx context.Context, orgS2R string, config *vaultDataSourceModel) (*vaultMatch, error) {
	if !config.ID.IsNull() && !config.ID.IsUnknown() {
		id := config.ID.ValueString()

		described, err := d.describe(ctx, id)
		if err != nil {
			return nil, fmt.Errorf("id %q: %w", id, err)
		}

		return &vaultMatch{VaultID: id, Name: described.GetLabel(), Described: described}, nil
	}

	name := config.Name.ValueString()

	match, err := d.findByName(ctx, orgS2R, name)
	if err != nil {
		return nil, fmt.Errorf("name %q: %w", name, err)
	}

	if match.Summary == nil {
		match.Described, err = d.describe(ctx, match.VaultID)
		if err != nil {
			return nil, fmt.Errorf("name %q: %w", name, err)
		}
	}

	return match, nil
}

func (d *vaultDataSource) describe(ctx context.Context, vaultID string) (*vaultbrowsev1.DescribeVaultResponse, error) {
	resp, err := d.client.VaultBrowse.DescribeVault(ctx, connect.NewRequest(&vaultbrowsev1.DescribeVaultRequest{
		Base: &vaultbrowsev1.DescribeVaultRequest_Base{VaultId: vaultID},
	}))
	if err != nil {
		return nil, fmt.Errorf("describing vault: %w", err)
	}

	return resp.Msg, nil
}

// applyMatch fills the attributes the match knows. A summary alone carries the team ids.
func applyMatch(ctx context.Context, m *vaultDataSourceModel, match *vaultMatch) diag.Diagnostics {
	if match.Described != nil {
		m.CustodyClass = types.StringValue(enumName(match.Described.GetCustodyClass().String(), "CUSTODY_CLASS_"))
		m.Status = types.StringValue(enumName(match.Described.GetStatus().String(), "VAULT_STATUS_"))
	}

	if match.Summary != nil {
		return applySummary(ctx, m, match.Summary)
	}

	return nil
}
