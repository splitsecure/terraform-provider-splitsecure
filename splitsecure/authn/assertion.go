package authn

import "time"

// assertionLifetime stays well under the server's five minute ceiling and
// absorbs clock skew between the client and the server.
const assertionLifetime = 60 * time.Second

// assertion signs the RFC 7523 assertion the token endpoint of issuer
// accepts. The account is both issuer and subject, and the audience is
// the issuer's exchange endpoint, so the assertion cannot be spent
// anywhere else.
func (k *Key) assertion(issuer string, now time.Time) (string, error) {
	jti, err := randomID()
	if err != nil {
		return "", err
	}

	return k.signer.sign(
		map[string]any{"typ": "JWT", "kid": k.KeyID},
		map[string]any{
			"iss": k.ServiceAccountS2R,
			"sub": k.ServiceAccountS2R,
			"aud": issuer + "/exchange",
			"iat": now.Unix(),
			"exp": now.Add(assertionLifetime).Unix(),
			"jti": jti,
		},
	)
}
