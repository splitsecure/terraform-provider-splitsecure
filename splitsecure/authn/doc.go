// Package authn authenticates a Go client to the SplitSecure API
// as a service account.
//
// A service account signs in with a registered private key. The client
// signs a short assertion with that key, trades it for an identity token
// at the deployment's token endpoint, and trades the identity token for a
// service token at the API's own exchange. Every request then carries the
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
package authn
