package saml2

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"

	saml2v2 "github.com/splitsecure/apis/gen/go/proto/splitsecure/saml2/v2"
)

// freshIDPState builds an IdPState with a fresh ECDSA cert valid 10
// years out. Used by tests that don't care about the cert bytes
// themselves, only that the cert parses and renders.
func freshIDPState(t *testing.T) *saml2v2.IdPState {
	t.Helper()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test-idp"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(10, 0, 0),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating test cert: %v", err)
	}

	return &saml2v2.IdPState{
		X509Certificate: der,
		ProviderId:      "https://idp.example.com/saml/idp/test",
		SsoUrl:          "https://companion.example.com/saml2/sp/login",
		SsoUrlPost:      "https://monolith.example.com/saml2/sp/login",
	}
}

// TestIdpMetadataXML_Idempotent asserts the renderer returns identical
// bytes across two calls with the same input. terraform refresh runs
// this on every plan; a non-idempotent renderer would show drift on
// every refresh even when the IdP hasn't changed.
func TestIdpMetadataXML_Idempotent(t *testing.T) {
	t.Parallel()

	state := freshIDPState(t)
	first, err := idpMetadataXML(state)
	if err != nil {
		t.Fatalf("idpMetadataXML (first call): %v", err)
	}
	second, err := idpMetadataXML(state)
	if err != nil {
		t.Fatalf("idpMetadataXML (second call): %v", err)
	}
	if !bytes.Equal(first, second) {
		t.Errorf("renderer not idempotent.\nfirst:\n%s\nsecond:\n%s", first, second)
	}
}

// TestIdpMetadataXML_HTTPPostOmitted asserts the HTTP-POST binding is
// only emitted when sso_url_post is set. Mirrors the conditional
// append in idpMetadataXML.
func TestIdpMetadataXML_HTTPPostOmitted(t *testing.T) {
	t.Parallel()

	state := freshIDPState(t)
	state.SsoUrlPost = ""
	got, err := idpMetadataXML(state)
	if err != nil {
		t.Fatalf("idpMetadataXML: %v", err)
	}
	if bytes.Contains(got, []byte("HTTP-POST")) {
		t.Errorf("HTTP-POST binding should be omitted when sso_url_post is empty:\n%s", got)
	}
	if !bytes.Contains(got, []byte("HTTP-Redirect")) {
		t.Errorf("HTTP-Redirect binding should always be present:\n%s", got)
	}
}

// TestIdpMetadataXML_RejectsUnparseableCert confirms a hard error
// surfaces when the cert bytes can't be parsed. validUntilFromCert
// would otherwise silently fall through to an empty validUntil and
// produce drift on every refresh.
func TestIdpMetadataXML_RejectsUnparseableCert(t *testing.T) {
	t.Parallel()

	state := &saml2v2.IdPState{
		X509Certificate: []byte("not a real cert"),
		ProviderId:      "https://idp.example.com/saml/idp/test",
		SsoUrl:          "https://companion.example.com/saml2/sp/login",
	}
	_, err := idpMetadataXML(state)
	if err == nil {
		t.Fatal("expected error from unparseable cert, got nil")
	}
}

// TestValidUntilFromCert_AnchorsToNotAfter asserts the rendered
// validUntil is the cert's NotAfter. This is the property that makes
// terraform refresh idempotent: NotAfter is set once at mint time and
// never changes for a given IdP.
func TestValidUntilFromCert_AnchorsToNotAfter(t *testing.T) {
	t.Parallel()

	notAfter := time.Date(2030, 6, 15, 12, 30, 45, 0, time.UTC)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generating test key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "test"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     notAfter,
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatalf("creating test cert: %v", err)
	}

	got, err := validUntilFromCert(der)
	if err != nil {
		t.Fatalf("validUntilFromCert: %v", err)
	}
	want := "2030-06-15T12:30:45Z"
	if got != want {
		t.Errorf("validUntilFromCert = %q, want %q", got, want)
	}
}
