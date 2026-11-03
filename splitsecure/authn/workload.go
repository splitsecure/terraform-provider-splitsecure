package authn

import (
	"context"
	"errors"
	"fmt"
	"net/url"
)

var (
	// ErrMissingTokenSource is returned when a Workload has no token source.
	ErrMissingTokenSource = errors.New("a workload identity needs a token source")
	// ErrEmptyWorkloadToken is returned when the token source yields no token.
	ErrEmptyWorkloadToken = errors.New("the token source returned an empty token")
)

// TokenSource returns a fresh external OIDC token whose aud claim is the
// given audience. It is called on every refresh and its result is never
// cached.
type TokenSource func(ctx context.Context, audience string) (string, error)

// Workload is a service account that signs in with an external OIDC token,
// for example one issued to a GitHub Actions job, instead of a key.
type Workload struct {
	// ServiceAccountS2R identifies the account, for example
	// s2r:us:sa:1234. The account must have a binding that matches the
	// token.
	ServiceAccountS2R string
	// TokenSource supplies the external token.
	TokenSource TokenSource
}

func (w *Workload) firstHopForm(ctx context.Context, audience string) (url.Values, error) {
	if w.ServiceAccountS2R == "" {
		return nil, ErrMissingAccount
	}
	if w.TokenSource == nil {
		return nil, ErrMissingTokenSource
	}

	token, err := w.TokenSource(ctx, audience)
	if err != nil {
		return nil, fmt.Errorf("fetching the workload identity token: %w", err)
	}
	if token == "" {
		return nil, ErrEmptyWorkloadToken
	}

	return url.Values{
		"grant_type":         {grantTokenExchange},
		"subject_token_type": {tokenTypeJWT},
		"subject_token":      {token},
		"service_account":    {w.ServiceAccountS2R},
	}, nil
}
