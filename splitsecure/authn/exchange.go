package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

const (
	identityExchangePath = "/authn/exchange"
	serviceExchangePath  = "/servicetoken/exchange"

	grantJWTBearer     = "urn:ietf:params:oauth:grant-type:jwt-bearer"     //nolint:gosec // an RFC grant-type URN, not a credential
	grantTokenExchange = "urn:ietf:params:oauth:grant-type:token-exchange" //nolint:gosec // an RFC grant-type URN, not a credential
	tokenTypeJWT       = "urn:ietf:params:oauth:token-type:jwt"            //nolint:gosec // an RFC token-type URN, not a credential

	maxBody = 64 << 10
)

// ErrNoAccessToken is returned when an exchange succeeds but returns no
// token.
var ErrNoAccessToken = errors.New("the exchange response carries no access_token")

// ExchangeError is the server's refusal of a token exchange, in the OAuth
// error shape.
type ExchangeError struct {
	// Status is the HTTP status code.
	Status int
	// Code is the OAuth error code, for example invalid_grant. Empty when
	// the body was not an OAuth error.
	Code string
	// Description is the server's reason, from error_description or message.
	Description string
}

func (e *ExchangeError) Error() string {
	switch {
	case e.Code == "":
		return fmt.Sprintf("the server refused the token exchange: HTTP %d", e.Status)
	case e.Description == "":
		return fmt.Sprintf("the server refused the token exchange (%s)", e.Code)
	default:
		return fmt.Sprintf("the server refused the token exchange: %s (%s)", e.Description, e.Code)
	}
}

// tokenResponse is the OAuth token response, so its field names are fixed
// by the RFC.
type tokenResponse struct {
	AccessToken string `json:"access_token"` //nolint:gosec,tagliatelle // RFC 6749 field name.
	ExpiresIn   int    `json:"expires_in"`   //nolint:tagliatelle // RFC 6749 field name.
}

// errorResponse reads the RFC 6749 error_description and the server's own message field.
type errorResponse struct {
	Error            string `json:"error"`
	ErrorDescription string `json:"error_description"` //nolint:tagliatelle // RFC 6749 field name.
	Message          string `json:"message"`
}

// credential produces the form of the first hop, the one that buys an
// identity token. It runs on every refresh.
type credential interface {
	firstHopForm(ctx context.Context, audience string) (url.Values, error)
}

// keyCredential proves the account by signing an assertion with its key.
type keyCredential struct {
	key    *Key
	issuer string
}

func (c keyCredential) firstHopForm(_ context.Context, audience string) (url.Values, error) {
	assertion, err := c.key.assertion(c.issuer, time.Now())
	if err != nil {
		return nil, err
	}

	return url.Values{
		"grant_type": {grantJWTBearer},
		"assertion":  {assertion},
		"audience":   {audience},
	}, nil
}

// exchanger turns a credential into a service token in two hops. The
// credential buys an identity token at the identity issuer, and the
// identity token buys a service token at the API's own exchange. Both are
// bound to the same DPoP key.
type exchanger struct {
	http      *http.Client
	endpoint  string
	host      string
	audience  string
	org       string
	userAgent string
	cred      credential
	dpop      *dpopKey
}

func (e *exchanger) serviceToken(ctx context.Context) (string, time.Time, error) {
	now := time.Now()

	form, err := e.cred.firstHopForm(ctx, e.audience)
	if err != nil {
		return "", time.Time{}, err
	}
	if e.org != "" {
		form.Set("organization", e.org)
	}
	identity, err := e.post(ctx, identityExchangePath, form)
	if err != nil {
		return "", time.Time{}, fmt.Errorf("exchanging the credential for an identity token: %w", err)
	}

	service, err := e.post(ctx, serviceExchangePath, url.Values{
		"grant_type":         {grantTokenExchange},
		"subject_token_type": {tokenTypeJWT},
		"subject_token":      {identity.AccessToken},
	})
	if err != nil {
		return "", time.Time{}, fmt.Errorf("exchanging the identity token for a service token: %w", err)
	}

	return service.AccessToken, now.Add(time.Duration(service.ExpiresIn) * time.Second), nil
}

func (e *exchanger) post(ctx context.Context, path string, form url.Values) (*tokenResponse, error) {
	// The server rebuilds htu from the Host header and the path with an
	// https scheme, whatever scheme the request arrived on.
	proof, err := e.dpop.proof(http.MethodPost, "https://"+e.host+path, "", time.Now())
	if err != nil {
		return nil, err
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, e.endpoint+path, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("building the exchange request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	req.Header.Set("DPoP", proof)
	if e.userAgent != "" {
		req.Header.Set("User-Agent", e.userAgent)
	}

	resp, err := e.http.Do(req) //nolint:gosec // the endpoint is operator configuration, not request input.
	if err != nil {
		return nil, fmt.Errorf("POST %s: %w", path, err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return nil, fmt.Errorf("reading the exchange response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return nil, refusal(resp.StatusCode, body)
	}

	var token tokenResponse
	err = json.Unmarshal(body, &token)
	if err != nil {
		return nil, fmt.Errorf("decoding the exchange response: %w", err)
	}
	if token.AccessToken == "" {
		return nil, ErrNoAccessToken
	}

	return &token, nil
}

func refusal(status int, body []byte) error {
	var detail errorResponse
	err := json.Unmarshal(body, &detail)
	if err != nil || detail.Error == "" {
		return &ExchangeError{Status: status}
	}

	description := detail.ErrorDescription
	if description == "" {
		description = detail.Message
	}

	return &ExchangeError{Status: status, Code: detail.Error, Description: description}
}
