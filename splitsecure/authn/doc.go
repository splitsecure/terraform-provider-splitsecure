// Package authn authenticates a Go client to the SplitSecure API
// as a service account.
//
// A service account signs in with a registered private key, or with an
// external OIDC token through workload identity. With a key, the client
// signs a short assertion and trades it for an identity token at the
// deployment's token endpoint. With workload identity, it trades a fresh
// external token, for example a GitHub Actions ID token, for the identity
// token. Either way, the identity token is then traded for a service token
// at the API's own exchange. Every request then carries the
// service token and a DPoP proof (RFC 9449) bound to a key the client
// generates at startup. [Transport] does all of this behind an
// http.RoundTripper, so a Connect client only needs to be built on an
// http.Client that uses it.
//
//	key, err := authn.ParseKey(accountS2R, keyID, pemBytes)
//	transport, err := authn.NewTransport(authn.Config{
//		Endpoint: "https://api.example.com",
//		Key:      key,
//	})
//	httpClient := &http.Client{Transport: transport}
//
// For workload identity inside GitHub Actions, set Workload instead of Key:
//
//	source, err := authn.GitHubActionsTokenSource(nil)
//	transport, err := authn.NewTransport(authn.Config{
//		Endpoint: "https://api.example.com",
//		Workload: &authn.Workload{ServiceAccountS2R: accountS2R, TokenSource: source},
//	})
package authn
