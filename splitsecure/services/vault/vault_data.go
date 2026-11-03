// Package vault implements the SplitSecure vault data source.
package vault

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/hashicorp/terraform-plugin-framework-validators/listvalidator"
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

const listVaultsPageSize = 100

var (
	errVaultNotFound  = errors.New("no vault matches")
	errVaultAmbig     = errors.New("more than one vault matches")
	errFolderNotFound = errors.New("folder does not resolve")
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
	Folder       types.List   `tfsdk:"folder"`
	NodeID       types.String `tfsdk:"node_id"`
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
		Description: "Resolves a vault by name or by id. Set exactly one of them. A name lookup errors when no vault or more than one vault has the name.",
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
				Description: "Org s2r URI to search. Defaults to the provider's org_s2r.",
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
			"folder": schema.ListAttribute{
				ElementType: types.StringType,
				Optional:    true,
				Description: "Folder path as labels from the vault root, for example [\"terraform\"]. Errors when the path does not resolve.",
				Validators:  []validator.List{listvalidator.SizeAtLeast(1)},
			},
			"node_id": schema.StringAttribute{
				Computed:    true,
				Description: "Node id of the folder. Null when folder is unset. Use it as parent_node_id of vault resources.",
			},
			"team_ids": schema.ListAttribute{
				ElementType: types.StringType,
				Computed:    true,
				Description: "Base64-encoded ids of the teams that hold the vault.",
			},
		},
	}
}

// vaultMatch is a vault found by name. Summary is nil when the vault is only reachable through shared nodes.
type vaultMatch struct {
	VaultID   string
	Name      string
	Summary   *vaultcatalogv1.VaultSummary
	Described *vaultbrowsev1.DescribeVaultResponse
	Shared    []*vaultcatalogv1.SharedNode
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
	config.NodeID = types.StringNull()

	resp.Diagnostics.Append(applyMatch(ctx, &config, match)...)

	if !config.Folder.IsNull() && !config.Folder.IsUnknown() {
		var segments []string

		resp.Diagnostics.Append(config.Folder.ElementsAs(ctx, &segments, false)...)

		if resp.Diagnostics.HasError() {
			return
		}

		nodeID, err := d.resolveFolderIn(ctx, match, segments)
		if err != nil {
			resp.Diagnostics.AddError("Resolving folder", fmt.Sprintf("path %q: %s", segments, err))

			return
		}

		config.NodeID = types.StringValue(nodeID)
	}

	if resp.Diagnostics.HasError() {
		return
	}

	resp.Diagnostics.Append(resp.State.Set(ctx, &config)...)
}

// findByName looks in the caller's member vaults, then in shared nodes, and errors unless exactly one vault matches.
func (d *vaultDataSource) findByName(ctx context.Context, orgS2R, name string) (*vaultMatch, error) {
	found := map[string]*vaultMatch{}

	err := d.eachVault(ctx, orgS2R, func(v *vaultcatalogv1.VaultSummary) {
		if v.GetLabel() == name {
			found[v.GetVaultId()] = &vaultMatch{VaultID: v.GetVaultId(), Name: v.GetLabel(), Summary: v}
		}
	})
	if err != nil {
		return nil, err
	}

	err = d.eachShared(ctx, orgS2R, func(n *vaultcatalogv1.SharedNode) {
		if n.GetVaultLabel() != name {
			return
		}

		m, ok := found[n.GetVaultId()]
		if !ok {
			m = &vaultMatch{VaultID: n.GetVaultId(), Name: n.GetVaultLabel()}
			found[n.GetVaultId()] = m
		}

		m.Shared = append(m.Shared, n)
	})
	if err != nil {
		return nil, err
	}

	switch len(found) {
	case 0:
		return nil, errVaultNotFound
	case 1:
		for _, m := range found {
			return m, nil
		}
	}

	return nil, errVaultAmbig
}

func (d *vaultDataSource) eachVault(ctx context.Context, orgS2R string, visit func(*vaultcatalogv1.VaultSummary)) error {
	var cursor []byte

	for {
		resp, err := d.client.VaultCatalog.ListVaults(ctx, connect.NewRequest(&vaultcatalogv1.ListVaultsRequest{
			Base: &vaultcatalogv1.ListVaultsRequest_Base{OrgS2R: orgS2R, Page: pageAt(cursor)},
		}))
		if err != nil {
			return fmt.Errorf("listing vaults: %w", err)
		}

		for _, v := range resp.Msg.GetVaults() {
			visit(v)
		}

		cursor = resp.Msg.GetNextCursor()
		if len(cursor) == 0 {
			return nil
		}
	}
}

func (d *vaultDataSource) eachShared(ctx context.Context, orgS2R string, visit func(*vaultcatalogv1.SharedNode)) error {
	var cursor []byte

	for {
		resp, err := d.client.VaultCatalog.ListSharedWithMe(ctx, connect.NewRequest(&vaultcatalogv1.ListSharedWithMeRequest{
			Base: &vaultcatalogv1.ListSharedWithMeRequest_Base{OrgS2R: orgS2R, Page: pageAt(cursor)},
		}))
		if err != nil {
			return fmt.Errorf("listing shared nodes: %w", err)
		}

		for _, n := range resp.Msg.GetSharedNodes() {
			visit(n)
		}

		cursor = resp.Msg.GetNextCursor()
		if len(cursor) == 0 {
			return nil
		}
	}
}

func pageAt(cursor []byte) *pagev1.PageParams {
	page := &pagev1.PageParams{Limit: listVaultsPageSize}
	if cursor != nil {
		page.DirectionOrCursor = &pagev1.PageParams_DirectionOrCursor{
			Union: &pagev1.PageParams_DirectionOrCursor_Cursor{Cursor: cursor},
		}
	}

	return page
}

// resolveFolderIn uses a shared folder node when the path is that single folder, and asks the server otherwise.
func (d *vaultDataSource) resolveFolderIn(ctx context.Context, match *vaultMatch, segments []string) (string, error) {
	if len(segments) == 1 {
		for _, n := range match.Shared {
			if n.GetNode().GetIsDir() && n.GetNode().GetLabel() == segments[0] {
				return n.GetNode().GetNodeId(), nil
			}
		}
	}

	return d.resolveFolder(ctx, match.VaultID, segments)
}

func (d *vaultDataSource) resolveFolder(ctx context.Context, vaultID string, segments []string) (string, error) {
	resp, err := d.client.VaultBrowse.ListNodes(ctx, connect.NewRequest(&vaultbrowsev1.ListNodesRequest{
		Base: &vaultbrowsev1.ListNodesRequest_Base{
			VaultId: vaultID,
			Locator: &vaultbrowsev1.NodeLocator{
				Union: &vaultbrowsev1.NodeLocator_LabelPath{LabelPath: &vaultbrowsev1.LabelPath{Segments: segments}},
			},
			Page: &pagev1.PageParams{Limit: 1},
		},
	}))
	if err != nil {
		return "", fmt.Errorf("listing nodes: %w", err)
	}

	if resp.Msg.GetResolvedNodeId() == "" {
		return "", errFolderNotFound
	}

	return resp.Msg.GetResolvedNodeId(), nil
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

		resp, err := d.client.VaultBrowse.DescribeVault(ctx, connect.NewRequest(&vaultbrowsev1.DescribeVaultRequest{
			Base: &vaultbrowsev1.DescribeVaultRequest_Base{VaultId: id},
		}))
		if err != nil {
			return nil, fmt.Errorf("id %q: describing vault: %w", id, err)
		}

		return &vaultMatch{VaultID: id, Name: resp.Msg.GetLabel(), Described: resp.Msg}, nil
	}

	name := config.Name.ValueString()

	match, err := d.findByName(ctx, orgS2R, name)
	if err != nil {
		return nil, fmt.Errorf("name %q: %w", name, err)
	}

	return match, nil
}

// applyMatch fills the attributes the lookup path knows. Shared-only vaults leave them null.
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
