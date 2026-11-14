package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
)

// signer signs JWS compact serializations with one key. ECDSA signatures
// use the JWS r||s encoding, not ASN.1.
type signer struct {
	alg        string
	hash       crypto.Hash
	ecdsaKey   *ecdsa.PrivateKey
	ed25519Key ed25519.PrivateKey
}

func (s *signer) sign(header, claims map[string]any) (string, error) {
	header["alg"] = s.alg

	headerJSON, err := json.Marshal(header)
	if err != nil {
		return "", fmt.Errorf("encoding the JWS header: %w", err)
	}
	claimsJSON, err := json.Marshal(claims)
	if err != nil {
		return "", fmt.Errorf("encoding the JWS claims: %w", err)
	}
	input := base64.RawURLEncoding.EncodeToString(headerJSON) + "." + base64.RawURLEncoding.EncodeToString(claimsJSON)

	sig, err := s.signBytes([]byte(input))
	if err != nil {
		return "", err
	}

	return input + "." + base64.RawURLEncoding.EncodeToString(sig), nil
}

func (s *signer) signBytes(input []byte) ([]byte, error) {
	if s.ed25519Key != nil {
		return ed25519.Sign(s.ed25519Key, input), nil
	}

	h := s.hash.New()
	h.Write(input)
	r, sv, err := ecdsa.Sign(rand.Reader, s.ecdsaKey, h.Sum(nil))
	if err != nil {
		return nil, fmt.Errorf("signing: %w", err)
	}

	size := (s.ecdsaKey.Curve.Params().BitSize + 7) / 8 //nolint:mnd // bits to bytes, rounded up.
	out := make([]byte, 2*size)                         //nolint:mnd // r and s, each one coordinate wide.
	r.FillBytes(out[:size])
	sv.FillBytes(out[size:])

	return out, nil
}

// randomID returns 128 bits of randomness as a URL-safe string, for jti
// claims.
func randomID() (string, error) {
	b := make([]byte, 16) //nolint:mnd // 128 bits.
	_, err := rand.Read(b)
	if err != nil {
		return "", fmt.Errorf("generating a random id: %w", err)
	}

	return base64.RawURLEncoding.EncodeToString(b), nil
}
