package authn

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
)

const (
	githubRequestURLEnv   = "ACTIONS_ID_TOKEN_REQUEST_URL"
	githubRequestTokenEnv = "ACTIONS_ID_TOKEN_REQUEST_TOKEN"
)

var (
	// ErrNotGitHubActions is returned when the GitHub Actions token request
	// variables are not set.
	ErrNotGitHubActions = errors.New("ACTIONS_ID_TOKEN_REQUEST_URL and ACTIONS_ID_TOKEN_REQUEST_TOKEN are not set: " +
		"run inside GitHub Actions with the id-token: write permission")
	// ErrGitHubToken is returned when GitHub refuses the token request or
	// answers without a token.
	ErrGitHubToken = errors.New("GitHub did not issue an ID token")
)

// GitHubActionsTokenSource returns a TokenSource that asks the GitHub
// Actions runner for an ID token. The job needs the id-token: write
// permission. A nil client means a client with a 30 second timeout.
func GitHubActionsTokenSource(client *http.Client) (TokenSource, error) {
	requestURL := os.Getenv(githubRequestURLEnv)
	requestToken := os.Getenv(githubRequestTokenEnv)
	if requestURL == "" || requestToken == "" {
		return nil, ErrNotGitHubActions
	}
	if client == nil {
		client = &http.Client{Timeout: defaultExchangeTimeout}
	}

	return func(ctx context.Context, audience string) (string, error) {
		return fetchGitHubToken(ctx, client, requestURL, requestToken, audience)
	}, nil
}

func fetchGitHubToken(ctx context.Context, client *http.Client, requestURL, requestToken, audience string) (string, error) {
	target, err := url.Parse(requestURL)
	if err != nil {
		return "", fmt.Errorf("parsing %s: %w", githubRequestURLEnv, err)
	}
	query := target.Query()
	query.Set("audience", audience)
	target.RawQuery = query.Encode()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target.String(), nil)
	if err != nil {
		return "", fmt.Errorf("building the GitHub token request: %w", err)
	}
	req.Header.Set("Authorization", "bearer "+requestToken)
	req.Header.Set("Accept", "application/json")

	resp, err := client.Do(req) //nolint:gosec // the URL comes from the runner environment, not request input.
	if err != nil {
		return "", fmt.Errorf("requesting the GitHub token: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBody))
	if err != nil {
		return "", fmt.Errorf("reading the GitHub token response: %w", err)
	}
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("%w: HTTP %d", ErrGitHubToken, resp.StatusCode)
	}

	var decoded struct {
		Value string `json:"value"`
	}
	err = json.Unmarshal(body, &decoded)
	if err != nil {
		return "", fmt.Errorf("decoding the GitHub token response: %w", err)
	}
	if decoded.Value == "" {
		return "", fmt.Errorf("%w: empty value", ErrGitHubToken)
	}

	return decoded.Value, nil
}
