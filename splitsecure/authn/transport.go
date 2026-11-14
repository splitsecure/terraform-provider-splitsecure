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
	// ErrMissingKey is returned by NewTransport when neither Config.Key nor
	// Config.Workload is set.
	ErrMissingKey = errors.New("a service account key or a workload identity is required")
	// ErrAmbiguousCredential is returned by NewTransport when both
	// Config.Key and Config.Workload are set.
	ErrAmbiguousCredential = errors.New("set either a service account key or a workload identity, not both")
	// ErrEndpoint is returned when the endpoint is not an absolute URL.
	ErrEndpoint = errors.New("the endpoint is not an absolute URL with no path")
	// ErrForeignHost is returned for a request to a host other than the
	// endpoint, which never receives the service token.
	ErrForeignHost = errors.New("the request is not for the endpoint host")
)

// Config is what NewTransport needs to reach one deployment as one
// service account.
type Config struct {
	// Endpoint is the API origin, for example https://api.example.com.
	// The token endpoints and the audience derive from it.
	Endpoint string
	// Key is the registered service account key to sign in with. Exactly
	// one of Key and Workload must be set.
	Key *Key
	// Workload signs in with an external OIDC token instead of a key.
	Workload *Workload
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
	host     string
	exchange *exchanger

	mu     sync.Mutex
	token  string
	expiry time.Time
}

// NewTransport builds a Transport. It generates the DPoP key but makes no
// network call; the first request triggers the first exchange.
func NewTransport(cfg Config) (*Transport, error) {
	endpoint := strings.TrimRight(cfg.Endpoint, "/")
	u, err := url.Parse(endpoint)
	if err != nil || u.Scheme == "" || u.Host == "" || u.Path != "" {
		return nil, fmt.Errorf("%w: %q", ErrEndpoint, cfg.Endpoint)
	}
	cred, err := credentialFor(cfg, endpoint)
	if err != nil {
		return nil, err
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
		host: u.Host,
		exchange: &exchanger{
			http:      exchangeClient,
			endpoint:  endpoint,
			host:      u.Host,
			audience:  strings.ToLower(u.Scheme + "://" + u.Host),
			org:       cfg.Organization,
			userAgent: cfg.UserAgent,
			cred:      cred,
			dpop:      dpop,
		},
	}, nil
}

func credentialFor(cfg Config, endpoint string) (credential, error) {
	switch {
	case cfg.Key != nil && cfg.Workload != nil:
		return nil, ErrAmbiguousCredential
	case cfg.Key != nil:
		return keyCredential{key: cfg.Key, issuer: endpoint + "/authn"}, nil
	case cfg.Workload != nil:
		return workloadCredential{workload: cfg.Workload, issuer: endpoint + "/authn"}, nil
	default:
		return nil, ErrMissingKey
	}
}

// RoundTrip implements http.RoundTripper.
func (t *Transport) RoundTrip(req *http.Request) (*http.Response, error) {
	if !strings.EqualFold(req.URL.Host, t.host) {
		closeBody(req)

		return nil, fmt.Errorf("%w: %q", ErrForeignHost, req.URL.Host)
	}

	token, err := t.serviceToken(req.Context())
	if err != nil {
		closeBody(req)

		return nil, err
	}

	proof, err := t.exchange.dpop.proof(req.Method, "https://"+req.URL.Host+req.URL.Path, token, time.Now())
	if err != nil {
		closeBody(req)

		return nil, err
	}

	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("DPoP", proof)

	return t.base.RoundTrip(req)
}

func closeBody(req *http.Request) {
	if req.Body != nil {
		_ = req.Body.Close()
	}
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
