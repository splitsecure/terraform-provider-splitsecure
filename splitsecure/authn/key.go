package authn

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
)

var (
	// ErrRSAKey is returned for RSA keys, which the server does not accept.
	ErrRSAKey = errors.New("RSA keys are not accepted: register an ECDSA P-256, P-384, P-521 or Ed25519 key")
	// ErrNotPEM is returned when the key bytes hold no PEM block.
	ErrNotPEM = errors.New("the private key is not a PEM block")
	// ErrPEMType is returned for a PEM block that is not a private key.
	ErrPEMType = errors.New("the PEM block is not a PRIVATE KEY (PKCS #8) or EC PRIVATE KEY (SEC 1) block")
	// ErrKeyType is returned for a private key that is neither ECDSA nor Ed25519.
	ErrKeyType = errors.New("the private key is not an ECDSA or Ed25519 key")
	// ErrCurve is returned for an ECDSA key on a curve other than P-256, P-384 or P-521.
	ErrCurve = errors.New("unsupported ECDSA curve")
	// ErrMissingAccount is returned when no service account identifier is given.
	ErrMissingAccount = errors.New("the service account identifier is required")
	// ErrMissingKeyID is returned when no key id is given.
	ErrMissingKeyID = errors.New("the key id is required")
)

// Key is a registered service account key: the account it belongs to, the
// key id the server assigned at registration and the private half.
type Key struct {
	// ServiceAccountS2R identifies the account, for example
	// s2r:us:sa:1234.
	ServiceAccountS2R string
	// KeyID is the kid the server returned when the public key was
	// registered.
	KeyID string

	signer *signer
}

// ParseKey reads a PEM private key and pairs it with the account and key
// id the server knows it by. PKCS #8 and SEC 1 blocks are accepted. The
// JWS algorithm follows the key: ES256, ES384 or ES512 for ECDSA and EdDSA
// for Ed25519.
func ParseKey(serviceAccountS2R, keyID string, pemText []byte) (*Key, error) {
	if serviceAccountS2R == "" {
		return nil, ErrMissingAccount
	}
	if keyID == "" {
		return nil, ErrMissingKeyID
	}

	key, err := decodePrivateKey(pemText)
	if err != nil {
		return nil, err
	}
	s, err := signerFor(key)
	if err != nil {
		return nil, err
	}

	return &Key{ServiceAccountS2R: serviceAccountS2R, KeyID: keyID, signer: s}, nil
}

func decodePrivateKey(pemText []byte) (any, error) {
	block, err := privateKeyBlock(pemText)
	if err != nil {
		return nil, err
	}

	var key any

	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		return nil, ErrRSAKey
	default:
		return nil, ErrPEMType
	}
	if err != nil {
		return nil, fmt.Errorf("parsing the private key: %w", err)
	}

	return key, nil
}

// privateKeyBlock returns the first PEM block, skipping the EC PARAMETERS
// block that openssl writes before an EC PRIVATE KEY.
func privateKeyBlock(pemText []byte) (*pem.Block, error) {
	rest := pemText
	for {
		var block *pem.Block

		block, rest = pem.Decode(rest)
		if block == nil {
			return nil, ErrNotPEM
		}

		if block.Type != "EC PARAMETERS" {
			return block, nil
		}
	}
}

func signerFor(key any) (*signer, error) {
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		return ecdsaSigner(k)
	case ed25519.PrivateKey:
		return &signer{alg: "EdDSA", ed25519Key: k}, nil
	case *rsa.PrivateKey:
		return nil, ErrRSAKey
	default:
		return nil, ErrKeyType
	}
}

func ecdsaSigner(k *ecdsa.PrivateKey) (*signer, error) {
	switch k.Curve {
	case elliptic.P256():
		return &signer{alg: "ES256", hash: crypto.SHA256, ecdsaKey: k}, nil
	case elliptic.P384():
		return &signer{alg: "ES384", hash: crypto.SHA384, ecdsaKey: k}, nil
	case elliptic.P521():
		return &signer{alg: "ES512", hash: crypto.SHA512, ecdsaKey: k}, nil
	default:
		return nil, fmt.Errorf("%w: %s", ErrCurve, k.Curve.Params().Name)
	}
}
