package vaultapi

import (
	"errors"
	"fmt"

	"google.golang.org/protobuf/proto"
	"google.golang.org/protobuf/types/known/emptypb"

	keysv1 "github.com/splitsecure/apis/gen/go/proto/splitsecure/keys/v1"
)

// JWS algorithm names accepted by the OIDC issuer.
const (
	AlgES256   = "ES256"
	AlgES384   = "ES384"
	AlgEdDSA   = "EdDSA"
	AlgMLDSA44 = "ML-DSA-44"
	AlgMLDSA65 = "ML-DSA-65"
	AlgMLDSA87 = "ML-DSA-87"
	AlgRS256   = "RS256"
)

const rs256Bits = 2048

var errUnsupportedAlg = errors.New("unsupported algorithm")

// AlgValues lists the accepted algorithm names.
func AlgValues() []string {
	return []string{AlgES256, AlgES384, AlgEdDSA, AlgMLDSA44, AlgMLDSA65, AlgMLDSA87, AlgRS256}
}

// SignatureSpecFromAlg maps a JWS algorithm name to a SignatureSpec.
func SignatureSpecFromAlg(alg string) (*keysv1.SignatureSpec, error) {
	switch alg {
	case AlgES256:
		return ecdsaSpec(keysv1.ECDSA_ECDSA_NIST_P256), nil
	case AlgES384:
		return ecdsaSpec(keysv1.ECDSA_ECDSA_NIST_P384), nil
	case AlgEdDSA:
		return &keysv1.SignatureSpec{Union: &keysv1.SignatureSpec_Eddsa{Eddsa: &keysv1.EDDSA{
			Union: &keysv1.EDDSA_Ed25519{Ed25519: &keysv1.EDDSA_ED25519{}},
		}}}, nil
	case AlgMLDSA44:
		return mldsaSpec(&keysv1.MLDSA{Union: &keysv1.MLDSA_V44{V44: &emptypb.Empty{}}}), nil
	case AlgMLDSA65:
		return mldsaSpec(&keysv1.MLDSA{Union: &keysv1.MLDSA_V65{V65: &emptypb.Empty{}}}), nil
	case AlgMLDSA87:
		return mldsaSpec(&keysv1.MLDSA{Union: &keysv1.MLDSA_V87{V87: &emptypb.Empty{}}}), nil
	case AlgRS256:
		return &keysv1.SignatureSpec{Union: &keysv1.SignatureSpec_Rsa{Rsa: &keysv1.RSA{
			Bits:            rs256Bits,
			SignatureScheme: keysv1.RSA_SIGNATURE_SCHEME_PKCS1V15,
		}}}, nil
	default:
		return nil, fmt.Errorf("%w %q", errUnsupportedAlg, alg)
	}
}

// AlgFromSignatureSpec maps a SignatureSpec back to its JWS algorithm name, or "" when it has none.
func AlgFromSignatureSpec(spec *keysv1.SignatureSpec) string {
	for _, alg := range AlgValues() {
		candidate, err := SignatureSpecFromAlg(alg)
		if err == nil && proto.Equal(candidate, spec) {
			return alg
		}
	}

	return ""
}

func ecdsaSpec(curve keysv1.ECDSA) *keysv1.SignatureSpec {
	return &keysv1.SignatureSpec{Union: &keysv1.SignatureSpec_Ecdsa{Ecdsa: curve}}
}

func mldsaSpec(m *keysv1.MLDSA) *keysv1.SignatureSpec {
	return &keysv1.SignatureSpec{Union: &keysv1.SignatureSpec_Mldsa{Mldsa: m}}
}
