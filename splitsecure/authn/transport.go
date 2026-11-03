package authn

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"time"
)

const (
	// refreshMargin is how long before expiry a cached service token is
	// replaced, so a request never leaves with a token about to lapse.
	refreshMargin = 2 * time.Minute

	defaultExchangeTimeout = 30 * time.Second
)

var (
	// ErrMissingKey is returned by NewTransport when Config.Key is nil.
	ErrMissingKey = errors.New("a service account key is required")
	// ErrEndpoint is returned when the endpoint is not an absolute URL.
	ErrEndpoint = errors.New("the endpoint is not an absolute URL")
)

// Config is what NewTransport needs to reach one deployment as one
// service account.
type Config struct {
	// Endpoint is the API origin, for example https://api.example.com.
	// The token endpoints and the audience derive from it.
	Endpoint string
	// Key is the registered service account key to sign in with.
	Key *Key
	// Organization is the s2r of the organization the account acts in.
	// Optional. When set, the identity token carries the account's group
	// memberships in that organization.
	Organization string
	// UserAgent is sent on the exchange requests. Optional.
	UserAgent string
	// Base is the RoundTripper API requests go through after the auth
	// headers are set. Defaults to http.DefaultTransport.
	Base http.RoundTripper
	// ExchangeClient performs the two token exchanges. Defaults to a client
	// with a 30 second timeout. It must not use this Transport.
	ExchangeClient *http.Client
}

// Transport is an http.RoundTripper that signs every request as the
// service account: it sets the Authorization header to the current
// service token and the DPoP header to a fresh proof, and exchanges a new
// token before the cached one expires. Concurrent requests on an expired
// token trigger one exchange, not one each.
type Transport struct {
	base     http.RoundTripper
	exchange *exchanger

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// NewTransport builds a Transport. It generates the DPoP key but makes no
// network call; the first request triggers the first exchange.
func NewTransport(cfg Config) (*Transport, error) {
	if cfg.Key == nil {
		return nil, ErrMissingKey
	}
	endpoint := strings.TrimRight(cfg.Endpoint, "/")
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return nil, fmt.Errorf("%w: %q", ErrEndpoint, cfg.Endpoint)
	}
	dpop, err := newDPoPKey()
	if err != nil {
		return nil, err
	}

	base := cfg.Base
	if base == nil {
		base = http.DefaultTransport
	}
	exchangeClient := cfg.ExchangeClient
	if exchangeClient == nil {
		exchangeClient = &http.Client{Timeout: defaultExchangeTimeout}
	}

	return &Transport{
		base: base,
		exchange: &exchanger{
			http:     exchangeClient,
			endpoint: endpoint,
			host:     u.Host,
			// The audience every identity token for a deployment names is
			// the lowercased origin of its endpoint.
			audience:  strings.ToLower(u.Scheme + "://" + u.Host),
			org:       cfg.Organization,
			userAgent: cfg.UserAgent,
			key:       cfg.Key,
			dpop:      dpop,
		},
	}, nil
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	token, err := t.serviceToken(req.Context())
	if err != nil {
		return nil, err
	}

	// The server rebuilds htu from the Host header and the path with an
	// https scheme, whatever scheme the request arrived on.
	proof, err := t.exchange.dpop.proof(req.Method, "https://"+req.URL.Host+req.URL.Path, token, time.Now())
	if err != nil {
		return nil, err
	}

	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("DPoP", proof)

	return t.base.RoundTrip(req)
}

func (t *Transport) serviceToken(ctx context.Context) (string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	if t.token != "" && time.Now().Before(t.expiry.Add(-refreshMargin)) {
		return t.token, nil
	}

	token, expiry, err := t.exchange.serviceToken(ctx)
	if err != nil {
		return "", err
	}
	t.token = token
	t.expiry = expiry

	return token, nil
}
