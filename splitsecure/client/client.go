// Package client provides the HTTP client for SplitSecure API calls.
package client

import (
	"net/http"
	"time"

	"github.com/hashicorp/go-retryablehttp"
	"github.com/hashicorp/terraform-plugin-log/tflog"

	conveniencestorev1connect "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/conveniencestore/v1/conveniencestorev1connect"
	enclaveroundtripv1connect "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/enclaveroundtrip/v1/enclaveroundtripv1connect"
	proposalsv1connect "github.com/splitsecure/terraform-provider-splitsecure/gen/go/proto/splitsecure/proposals/v1/proposalsv1connect"
)

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
	OrgS2R                  string
}

// New creates a Client with retries, timeouts, and bearer auth. The
// overall HTTP timeout is sized for long-running proposal polls: tf
// create/delete waits out voter approval over many minutes, so
// individual RPC calls see unary polls but the wrapper keeps the
// connection pool happy across retries.
func New(endpoint, bearerToken, orgS2R, version string) *Client {
	retryClient := retryablehttp.NewClient()
	retryClient.RetryMax = 3
	retryClient.Logger = nil

	httpClient := retryClient.StandardClient()
	httpClient.Timeout = 1 * time.Minute
	httpClient.Transport = &loggingTransport{
		token:     bearerToken,
		userAgent: "terraform-provider-splitsecure/" + version,
		wrapped:   httpClient.Transport,
	}

	return &Client{
		ConvenienceStoreService: conveniencestorev1connect.NewConvenienceStoreServiceClient(httpClient, endpoint),
		EnclaveRoundtripService: enclaveroundtripv1connect.NewEnclaveRoundtripServiceClient(httpClient, endpoint),
		ProposalsService:        proposalsv1connect.NewProposalsServiceClient(httpClient, endpoint),
		OrgS2R:                  orgS2R,
	}
}

type loggingTransport struct {
	token     string
	userAgent string
	wrapped   http.RoundTripper
}

func (t *loggingTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	ctx := req.Context()

	req = req.Clone(ctx)
	req.Header.Set("Authorization", "Bearer "+t.token)
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
