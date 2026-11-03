package vault

import (
	"context"
	"errors"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/datasource"

	vaultcatalogv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultcatalog/v1"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/vaultapi/vaultfake"
)

func TestVaultSchema_Attributes(t *testing.T) {
	t.Parallel()

	resp := &datasource.SchemaResponse{}
	NewVaultDataSource().Schema(context.Background(), datasource.SchemaRequest{}, resp)

	if resp.Diagnostics.HasError() {
		t.Fatalf("schema diagnostics: %v", resp.Diagnostics)
	}

	if !resp.Schema.Attributes["label"].IsRequired() {
		t.Error("label should be Required")
	}

	if !resp.Schema.Attributes["org_s2r"].IsOptional() {
		t.Error("org_s2r should be Optional")
	}

	for _, name := range []string{"id", "custody_class", "status", "team_ids"} {
		attr, ok := resp.Schema.Attributes[name]
		if !ok || !attr.IsComputed() {
			t.Errorf("attribute %q should be Computed", name)
		}
	}
}

func catalogWith(pages ...*vaultcatalogv1.ListVaultsResponse) *vaultfake.Catalog {
	calls := 0

	return &vaultfake.Catalog{
		OnListVaults: func(*vaultcatalogv1.ListVaultsRequest) (*vaultcatalogv1.ListVaultsResponse, error) {
			page := pages[calls]
			calls++

			return page, nil
		},
	}
}

func TestFindByLabel_PagesUntilMatch(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Catalog: catalogWith(
		&vaultcatalogv1.ListVaultsResponse{
			Vaults:     []*vaultcatalogv1.VaultSummary{{VaultId: "v1", Label: "other"}},
			NextCursor: []byte("next"),
		},
		&vaultcatalogv1.ListVaultsResponse{
			Vaults: []*vaultcatalogv1.VaultSummary{{VaultId: "v2", Label: "prod"}},
		},
	)})

	got, err := (&vaultDataSource{client: c}).findByLabel(context.Background(), "s2r:test:org:acme", "prod")
	if err != nil {
		t.Fatalf("findByLabel: %v", err)
	}

	if got.GetVaultId() != "v2" {
		t.Errorf("vault id = %q, want v2", got.GetVaultId())
	}
}

func TestFindByLabel_ErrorsOnNoMatch(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Catalog: catalogWith(
		&vaultcatalogv1.ListVaultsResponse{Vaults: []*vaultcatalogv1.VaultSummary{{VaultId: "v1", Label: "other"}}},
	)})

	_, err := (&vaultDataSource{client: c}).findByLabel(context.Background(), "s2r:test:org:acme", "prod")
	if !errors.Is(err, errVaultNotFound) {
		t.Fatalf("err = %v, want errVaultNotFound", err)
	}
}

func TestFindByLabel_ErrorsOnAmbiguousMatch(t *testing.T) {
	t.Parallel()

	c := vaultfake.New(t, vaultfake.Handlers{Catalog: catalogWith(
		&vaultcatalogv1.ListVaultsResponse{
			Vaults:     []*vaultcatalogv1.VaultSummary{{VaultId: "v1", Label: "prod"}},
			NextCursor: []byte("next"),
		},
		&vaultcatalogv1.ListVaultsResponse{Vaults: []*vaultcatalogv1.VaultSummary{{VaultId: "v2", Label: "prod"}}},
	)})

	_, err := (&vaultDataSource{client: c}).findByLabel(context.Background(), "s2r:test:org:acme", "prod")
	if !errors.Is(err, errVaultAmbig) {
		t.Fatalf("err = %v, want errVaultAmbig", err)
	}
}
