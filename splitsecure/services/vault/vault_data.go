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
	Label        types.String `tfsdk:"label"`
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

// vaultMatch is a vault found by label. Summary is nil when the vault is only reachable through shared nodes.
type vaultMatch struct {
	VaultID string
	Summary *vaultcatalogv1.VaultSummary
	Shared  []*vaultcatalogv1.SharedNode
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

	config.ID = types.StringValue(match.VaultID)
	config.OrgS2R = types.StringValue(orgS2R)
	config.CustodyClass = types.StringNull()
	config.Status = types.StringNull()
	config.TeamIDs = types.ListNull(types.StringType)
	config.NodeID = types.StringNull()

	if match.Summary != nil {
		resp.Diagnostics.Append(applySummary(ctx, &config, match.Summary)...)
	}

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

// findByLabel looks in the caller's member vaults, then in shared nodes, and errors unless exactly one vault matches.
func (d *vaultDataSource) findByLabel(ctx context.Context, orgS2R, label string) (*vaultMatch, error) {
	found := map[string]*vaultMatch{}

	err := d.eachVault(ctx, orgS2R, func(v *vaultcatalogv1.VaultSummary) {
		if v.GetLabel() == label {
			found[v.GetVaultId()] = &vaultMatch{VaultID: v.GetVaultId(), Summary: v}
		}
	})
	if err != nil {
		return nil, err
	}

	err = d.eachShared(ctx, orgS2R, func(n *vaultcatalogv1.SharedNode) {
		if n.GetVaultLabel() != label {
			return
		}

		m, ok := found[n.GetVaultId()]
		if !ok {
			m = &vaultMatch{VaultID: n.GetVaultId()}
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
	m.CustodyClass = types.StringValue(strings.ToLower(strings.TrimPrefix(v.GetCustodyClass().String(), "CUSTODY_CLASS_")))
	m.Status = types.StringValue(strings.ToLower(strings.TrimPrefix(v.GetStatus().String(), "VAULT_STATUS_")))

	teamIDs := make([]string, 0, len(v.GetTeamIds()))
	for _, id := range v.GetTeamIds() {
		teamIDs = append(teamIDs, base64.StdEncoding.EncodeToString(id))
	}

	var diags diag.Diagnostics

	m.TeamIDs, diags = types.ListValueFrom(ctx, types.StringType, teamIDs)

	return diags
}
