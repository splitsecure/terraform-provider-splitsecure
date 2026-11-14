package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"fmt"
	"net/url"
	"strings"
	"time"
)

const p256CoordLen = 32

// dpopKey is the P-256 key every token and request proof is bound to for
// the life of the transport (RFC 9449). The server only accepts ES256.
type dpopKey struct {
	signer *signer
	jwk    map[string]string
}

func newDPoPKey() (*dpopKey, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generating the DPoP key: %w", err)
	}

	x := make([]byte, p256CoordLen)
	y := make([]byte, p256CoordLen)
	key.X.FillBytes(x)
	key.Y.FillBytes(y)

	return &dpopKey{
		signer: &signer{alg: "ES256", hash: crypto.SHA256, ecdsaKey: key},
		jwk: map[string]string{
			"kty": "EC",
			"crv": "P-256",
			"x":   base64.RawURLEncoding.EncodeToString(x),
			"y":   base64.RawURLEncoding.EncodeToString(y),
		},
	}, nil
}

// proof signs the DPoP proof for one request. accessToken is empty on the
// exchange endpoints and the service token on every API request, where the
// server checks its hash in ath.
func (d *dpopKey) proof(method, htu, accessToken string, now time.Time) (string, error) {
	jti, err := randomID()
	if err != nil {
		return "", err
	}

	claims := map[string]any{
		"htm": strings.ToUpper(method),
		"htu": canonicalHTU(htu),
		"iat": now.Unix(),
		"jti": jti,
	}
	if accessToken != "" {
		sum := sha256.Sum256([]byte(accessToken))
		claims["ath"] = base64.RawURLEncoding.EncodeToString(sum[:])
	}

	return d.signer.sign(map[string]any{"typ": "dpop+jwt", "jwk": d.jwk}, claims)
}

// canonicalHTU strips the query and fragment (RFC 9449 section 4.2).
func canonicalHTU(raw string) string {
	u, err := url.Parse(raw)
	if err != nil {
		return raw
	}
	u.RawQuery = ""
	u.Fragment = ""

	return u.String()
}
