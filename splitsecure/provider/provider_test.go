package provider

import (
	"encoding/pem"
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestTransportWithRoots_RejectsBadPEM(t *testing.T) {
	t.Parallel()

	for name, pem := range map[string]string{
		"not pem":       "not a certificate",
		"wrong block":   "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----\n",
		"empty content": " ",
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			_, err := transportWithRoots(pem)
			if !errors.Is(err, ErrNoCertificate) {
				t.Fatalf("err = %v, want ErrNoCertificate", err)
			}
		})
	}
}

func TestTransportWithRoots_AcceptsCertificate(t *testing.T) {
	t.Parallel()

	srv := httptest.NewTLSServer(http.NotFoundHandler())
	t.Cleanup(srv.Close)
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: srv.Certificate().Raw})

	rt, err := transportWithRoots(string(caPEM))
	if err != nil {
		t.Fatal(err)
	}
	if rt == nil {
		t.Fatal("no transport")
	}
}
