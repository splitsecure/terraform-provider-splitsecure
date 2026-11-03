// Package client provides the HTTP client for SplitSecure API calls.
package client

import (
	"net/http"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	conveniencestorev1connect "github.com/splitsecure/apis/gen/go/proto/splitsecure/conveniencestore/v1/conveniencestorev1connect"
	enclaveroundtripv1connect "github.com/splitsecure/apis/gen/go/proto/splitsecure/enclaveroundtrip/v1/enclaveroundtripv1connect"
	orgsvcv1connect "github.com/splitsecure/apis/gen/go/proto/splitsecure/orgsvc/v1/orgsvcv1connect"
	proposalsv1connect "github.com/splitsecure/apis/gen/go/proto/splitsecure/proposals/v1/proposalsv1connect"
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
}

// Client wraps the SplitSecure Connect RPC clients plus the
// provider-level org_s2r used for proposal-scoped enclave spawning.
// org_s2r is provider-scoped (not per-resource) because Send is the
// only call that uses it -- once a proposal lands, every later
// reference is by resource_s2r / proposal_id, neither of which
// depends on the org. Multi-org users alias the provider.
type Client struct {
	ConvenienceStoreService conveniencestorev1connect.ConvenienceStoreServiceClient
	EnclaveRoundtripService enclaveroundtripv1connect.EnclaveRoundtripServiceClient
	ProposalsService        proposalsv1connect.ProposalsServiceClient
	OrgService              orgsvcv1connect.OrgServiceClient
	OrgS2R                  string
}

// New creates a Client with retries, timeouts, and service account auth.
// The overall HTTP timeout is sized for long-running proposal polls: tf
// create/delete waits out voter approval over many minutes, so
// individual RPC calls see unary polls but the wrapper keeps the
// connection pool happy across retries.
func New(cfg Config) (*Client, error) {
	userAgent := "terraform-provider-splitsecure/" + cfg.Version

	// One transport, so every client shares the service token and the DPoP
	// key it is bound to.
	auth, err := authn.NewTransport(authn.Config{
		Endpoint:     cfg.Endpoint,
		Key:          cfg.Key,
		Organization: cfg.OrgS2R,
		UserAgent:    userAgent,
	})
	if err != nil {
		return nil, err
	}
	logged := &loggingTransport{userAgent: userAgent, wrapped: auth}

	// Retrying client for the long-running enclave / proposal flow.
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.Logger = nil
	retryClient.HTTPClient.Transport = logged
	httpClient := retryClient.StandardClient()
	httpClient.Timeout = 1 * time.Minute

	// OrgService carries non-idempotent mutations (CreateGroup / UpdateGroup /
	// DeleteGroup / PutGrant / DeleteGrant). Every Connect RPC is a POST, so
	// retryablehttp can't scope retries by method and would replay a committed
	// write if the response is lost. Give it a non-retrying client; resource
	// create paths that need it do their own bounded, condition-scoped retries.
	orgHTTPClient := &http.Client{
		Timeout:   1 * time.Minute,
		Transport: logged,
	}

	return &Client{
		ConvenienceStoreService: conveniencestorev1connect.NewConvenienceStoreServiceClient(httpClient, cfg.Endpoint),
		EnclaveRoundtripService: enclaveroundtripv1connect.NewEnclaveRoundtripServiceClient(httpClient, cfg.Endpoint),
		ProposalsService:        proposalsv1connect.NewProposalsServiceClient(httpClient, cfg.Endpoint),
		OrgService:              orgsvcv1connect.NewOrgServiceClient(orgHTTPClient, cfg.Endpoint),
		OrgS2R:                  cfg.OrgS2R,
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
