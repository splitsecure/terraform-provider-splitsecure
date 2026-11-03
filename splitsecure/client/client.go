// Package client provides the HTTP client for SplitSecure API calls.
package client

import (
	"net/http"
	"time"

	"github.com/hashicorp/terraform-plugin-log/tflog"

	orgsvcv1connect "github.com/splitsecure/apis/gen/go/proto/splitsecure/orgsvc/v1/orgsvcv1connect"
	vaultbrowsev1connect "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultbrowse/v1/vaultbrowsev1connect"
	vaultcatalogv1connect "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultcatalog/v1/vaultcatalogv1connect"
	vaultusev1connect "github.com/splitsecure/apis/gen/go/proto/splitsecure/vaultuse/v1/vaultusev1connect"
	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/authn"
)

// Config is what New needs to reach one deployment as one service account.
type Config struct {
	// Endpoint is the API origin, for example https://monolith.example.com.
	Endpoint string
	// OrgS2R is the org the provider acts in; see Client.OrgS2R.
	OrgS2R  string
	Version string
	Key     *authn.Key
	// Workload signs in with an external OIDC token instead of Key.
	Workload *authn.Workload
}

// Client wraps the SplitSecure Connect RPC clients plus the provider-level
// org_s2r, which the vault data source uses as its default org.
type Client struct {
	OrgService   orgsvcv1connect.OrgServiceClient
	VaultUse     vaultusev1connect.VaultUseServiceClient
	VaultBrowse  vaultbrowsev1connect.VaultBrowseServiceClient
	VaultCatalog vaultcatalogv1connect.VaultCatalogServiceClient
	OrgS2R       string
}

// New creates a Client with timeouts and service account auth.
func New(cfg Config) (*Client, error) {
	userAgent := "terraform-provider-splitsecure/" + cfg.Version

	// One transport, so every client shares the service token and the DPoP
	// key it is bound to.
	auth, err := authn.NewTransport(authn.Config{
		Endpoint:     cfg.Endpoint,
		Key:          cfg.Key,
		Workload:     cfg.Workload,
		Organization: cfg.OrgS2R,
		UserAgent:    userAgent,
	})
	if err != nil {
		return nil, err
	}
	logged := &loggingTransport{userAgent: userAgent, wrapped: auth}

	// Every Connect RPC is a POST, so a retrying client would replay a
	// committed write if the response is lost. All clients are non-retrying;
	// resource create paths that need retries do their own bounded,
	// condition-scoped ones.
	httpClient := &http.Client{
		Timeout:   1 * time.Minute,
		Transport: logged,
	}

	// A vault create may wait on approvers and PollTicket is a long poll, so
	// the call context bounds the request instead of a client timeout.
	vaultUseHTTPClient := &http.Client{Transport: logged}

	return &Client{
		OrgService:   orgsvcv1connect.NewOrgServiceClient(httpClient, cfg.Endpoint),
		VaultUse:     vaultusev1connect.NewVaultUseServiceClient(vaultUseHTTPClient, cfg.Endpoint),
		VaultBrowse:  vaultbrowsev1connect.NewVaultBrowseServiceClient(httpClient, cfg.Endpoint),
		VaultCatalog: vaultcatalogv1connect.NewVaultCatalogServiceClient(httpClient, cfg.Endpoint),
		OrgS2R:       cfg.OrgS2R,
	}, nil
}

type loggingTransport struct {
	userAgent string
	wrapped   http.RoundTripper
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	req = req.Clone(ctx)
	req.Header.Set("User-Agent", t.userAgent)

	tflog.Debug(ctx, "API request", map[string]any{
		"method": req.Method,
		"url":    req.URL.String(),
	})

	resp, err := t.wrapped.RoundTrip(req)
	if err != nil {
		tflog.Error(ctx, "API request failed", map[string]any{
			"method": req.Method,
			"url":    req.URL.String(),
			"error":  err.Error(),
		})

		return nil, err
	}

	tflog.Debug(ctx, "API response", map[string]any{
		"method": req.Method,
		"url":    req.URL.String(),
		"status": resp.StatusCode,
	})

	return resp, nil
}
