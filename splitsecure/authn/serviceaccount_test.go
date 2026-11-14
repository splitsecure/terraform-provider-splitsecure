package authn

import (
	"context"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

const testAccount = "s2r:test:sa:42"

func pemPKCS8(t *testing.T, key any) []byte {
	t.Helper()
	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der})
}

func p256Key(t *testing.T) *ecdsa.PrivateKey {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	return key
}

func testKey(t *testing.T) *Key {
	t.Helper()
	key, err := ParseKey(testAccount, "kid-1", pemPKCS8(t, p256Key(t)))
	if err != nil {
		t.Fatal(err)
	}

	return key
}

// jws is a decoded compact serialization, not verified.
type jws struct {
	header map[string]any
	claims map[string]any
	input  string
	sig    []byte
}

func decodeJWS(t *testing.T, token string) jws {
	t.Helper()
	parts := strings.Split(token, ".")
	if len(parts) != 3 { //nolint:mnd // header, claims, signature.
		t.Fatalf("JWS has %d parts, want 3", len(parts))
	}
	decoded := jws{input: parts[0] + "." + parts[1]}
	for i, dst := range []*map[string]any{&decoded.header, &decoded.claims} {
		raw, err := base64.RawURLEncoding.DecodeString(parts[i])
		if err != nil {
			t.Fatal(err)
		}
		err = json.Unmarshal(raw, dst)
		if err != nil {
			t.Fatal(err)
		}
	}
	sig, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		t.Fatal(err)
	}
	decoded.sig = sig

	return decoded
}

func verifyES256(t *testing.T, pub *ecdsa.PublicKey, j jws) {
	t.Helper()
	if len(j.sig) != 2*p256CoordLen {
		t.Fatalf("ES256 signature is %d bytes, want 64", len(j.sig))
	}
	digest := sha256.Sum256([]byte(j.input))
	r := new(big.Int).SetBytes(j.sig[:p256CoordLen])
	s := new(big.Int).SetBytes(j.sig[p256CoordLen:])
	if !ecdsa.Verify(pub, digest[:], r, s) {
		t.Fatal("ES256 signature does not verify")
	}
}

// post sends an empty POST and returns the status code, or the error the
// transport produced before any request left.
func post(t *testing.T, client *http.Client, target string) (int, error) {
	t.Helper()
	req, err := http.NewRequestWithContext(context.Background(), http.MethodPost, target, nil)
	if err != nil {
		t.Fatal(err)
	}
	resp, err := client.Do(req) //nolint:gosec // the target is a test server URL.
	if err != nil {
		return 0, err
	}
	defer func() { _ = resp.Body.Close() }()

	return resp.StatusCode, nil
}

func mustPost(t *testing.T, client *http.Client, target string) int {
	t.Helper()
	status, err := post(t, client, target)
	if err != nil {
		t.Fatal(err)
	}

	return status
}

func TestParseKey_Algorithms(t *testing.T) {
	t.Parallel()

	p384, err := ecdsa.GenerateKey(elliptic.P384(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	_, ed, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	p256 := p256Key(t)
	sec1, err := x509.MarshalECPrivateKey(p256)
	if err != nil {
		t.Fatal(err)
	}

	sec1PEM := pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: sec1})
	ecParams := pem.EncodeToMemory(&pem.Block{Type: "EC PARAMETERS", Bytes: []byte{6, 8, 42, 134, 72, 206, 61, 3, 1, 7}})

	cases := map[string]struct {
		pem  []byte
		want string
	}{
		"p256 pkcs8":                    {pemPKCS8(t, p256), "ES256"},
		"p256 sec1":                     {sec1PEM, "ES256"},
		"p256 sec1 after ec parameters": {append(ecParams, sec1PEM...), "ES256"},
		"p384 pkcs8":                    {pemPKCS8(t, p384), "ES384"},
		"ed25519":                       {pemPKCS8(t, ed), "EdDSA"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			key, err := ParseKey(testAccount, "kid-1", tc.pem)
			if err != nil {
				t.Fatal(err)
			}
			if key.signer.alg != tc.want {
				t.Fatalf("alg = %s, want %s", key.signer.alg, tc.want)
			}
		})
	}
}

func TestParseKey_Rejects(t *testing.T) {
	t.Parallel()

	valid := pemPKCS8(t, p256Key(t))
	cases := map[string]struct {
		account, kid string
		pem          []byte
		want         error
	}{
		"rsa block":         {testAccount, "kid", pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: []byte{1}}), ErrRSAKey},
		"plain text":        {testAccount, "kid", []byte("not pem"), ErrNotPEM},
		"certificate block": {testAccount, "kid", pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: []byte{1}}), ErrPEMType},
		"empty account":     {"", "kid", valid, ErrMissingAccount},
		"empty key id":      {testAccount, "", valid, ErrMissingKeyID},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := ParseKey(tc.account, tc.kid, tc.pem)
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestAssertion(t *testing.T) {
	t.Parallel()

	priv := p256Key(t)
	key, err := ParseKey(testAccount, "kid-7", pemPKCS8(t, priv))
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)

	token, err := key.assertion("https://api.example.com/authn", now)
	if err != nil {
		t.Fatal(err)
	}
	j := decodeJWS(t, token)
	verifyES256(t, &priv.PublicKey, j)

	wantHeader := map[string]any{"alg": "ES256", "kid": "kid-7", "typ": "JWT"}
	for k, v := range wantHeader {
		if j.header[k] != v {
			t.Errorf("header %s = %v, want %v", k, j.header[k], v)
		}
	}
	wantClaims := map[string]any{
		"iss": testAccount,
		"sub": testAccount,
		"aud": "https://api.example.com/authn/exchange",
		"iat": float64(now.Unix()),
		"exp": float64(now.Add(assertionLifetime).Unix()),
	}
	for k, v := range wantClaims {
		if j.claims[k] != v {
			t.Errorf("claim %s = %v, want %v", k, j.claims[k], v)
		}
	}
	if jti, _ := j.claims["jti"].(string); len(jti) < 8 || len(jti) > 128 {
		t.Errorf("jti = %q, want 8 to 128 characters", jti)
	}
}

func TestAssertion_Ed25519(t *testing.T) {
	t.Parallel()

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ParseKey(testAccount, "kid-ed", pemPKCS8(t, priv))
	if err != nil {
		t.Fatal(err)
	}
	token, err := key.assertion("https://api.example.com/authn", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	j := decodeJWS(t, token)
	if j.header["alg"] != "EdDSA" {
		t.Fatalf("alg = %v", j.header["alg"])
	}
	if !ed25519.Verify(pub, []byte(j.input), j.sig) {
		t.Fatal("EdDSA signature does not verify")
	}
}

func TestDPoPProof(t *testing.T) {
	t.Parallel()

	d, err := newDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)

	proof, err := d.proof("post", "https://api.example.com/svc/Method?x=1#frag", "token-1", now)
	if err != nil {
		t.Fatal(err)
	}
	j := decodeJWS(t, proof)
	verifyES256(t, &d.signer.ecdsaKey.PublicKey, j)

	assertDPoPHeader(t, j.header)
	sum := sha256.Sum256([]byte("token-1"))
	wantClaims := map[string]any{
		"htm": "POST",
		"htu": "https://api.example.com/svc/Method",
		"ath": base64.RawURLEncoding.EncodeToString(sum[:]),
		"iat": float64(now.Unix()),
	}
	for k, v := range wantClaims {
		if j.claims[k] != v {
			t.Errorf("claim %s = %v, want %v", k, j.claims[k], v)
		}
	}
}

func assertDPoPHeader(t *testing.T, header map[string]any) {
	t.Helper()
	if header["typ"] != "dpop+jwt" || header["alg"] != "ES256" {
		t.Errorf("header = %v", header)
	}
	jwk, _ := header["jwk"].(map[string]any)
	if jwk["kty"] != "EC" || jwk["crv"] != "P-256" || jwk["x"] == "" || jwk["y"] == "" {
		t.Errorf("jwk = %v", jwk)
	}
}

func TestDPoPProof_NoTokenNoATH(t *testing.T) {
	t.Parallel()

	d, err := newDPoPKey()
	if err != nil {
		t.Fatal(err)
	}
	proof, err := d.proof("POST", "https://api.example.com/authn/exchange", "", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	if j := decodeJWS(t, proof); j.claims["ath"] != nil {
		t.Fatalf("ath set without a token: %v", j.claims["ath"])
	}
}

// fakeServer serves the two exchanges and one protected RPC, checking the
// headers the real server checks.
type fakeServer struct {
	*httptest.Server

	t          *testing.T
	expiresIn  int
	identities atomic.Int32
	services   atomic.Int32
	rpcs       atomic.Int32
}

func newFakeServer(t *testing.T, expiresIn int) *fakeServer {
	t.Helper()
	f := &fakeServer{t: t, expiresIn: expiresIn}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /authn/exchange", f.identityExchange)
	mux.HandleFunc("POST /servicetoken/exchange", f.serviceExchange)
	mux.HandleFunc("POST /svc.Service/Method", f.rpc)
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)

	return f
}

func (f *fakeServer) writeToken(w http.ResponseWriter, token string) {
	body, err := json.Marshal(map[string]any{"access_token": token, "expires_in": f.expiresIn})
	if err != nil {
		f.t.Error(err)

		return
	}
	_, _ = w.Write(body)
}

func (f *fakeServer) proofClaims(r *http.Request, path string) map[string]any {
	f.t.Helper()
	proof := r.Header.Get("DPoP")
	if proof == "" {
		f.t.Errorf("%s: no DPoP header", path)

		return nil
	}
	j := decodeJWS(f.t, proof)
	if j.header["typ"] != "dpop+jwt" {
		f.t.Errorf("%s: typ = %v", path, j.header["typ"])
	}
	if want := "https://" + r.Host + path; j.claims["htu"] != want {
		f.t.Errorf("%s: htu = %v, want %s", path, j.claims["htu"], want)
	}
	if j.claims["htm"] != "POST" {
		f.t.Errorf("%s: htm = %v", path, j.claims["htm"])
	}

	return j.claims
}

func (f *fakeServer) identityExchange(w http.ResponseWriter, r *http.Request) {
	f.identities.Add(1)
	_ = r.ParseForm()
	if r.PostForm.Get("grant_type") != grantJWTBearer {
		f.t.Errorf("grant_type = %q", r.PostForm.Get("grant_type"))
	}
	if r.PostForm.Get("audience") != strings.ToLower(f.URL) {
		f.t.Errorf("audience = %q, want %q", r.PostForm.Get("audience"), f.URL)
	}
	if r.PostForm.Get("organization") != "s2r:test:org:1" {
		f.t.Errorf("organization = %q", r.PostForm.Get("organization"))
	}
	if j := decodeJWS(f.t, r.PostForm.Get("assertion")); j.claims["aud"] != f.URL+"/authn/exchange" {
		f.t.Errorf("assertion aud = %v", j.claims["aud"])
	}
	if c := f.proofClaims(r, "/authn/exchange"); c != nil && c["ath"] != nil {
		f.t.Error("identity exchange proof carries ath")
	}
	f.writeToken(w, "identity-1")
}

func (f *fakeServer) serviceExchange(w http.ResponseWriter, r *http.Request) {
	n := f.services.Add(1)
	_ = r.ParseForm()
	if r.PostForm.Get("grant_type") != grantTokenExchange || r.PostForm.Get("subject_token_type") != tokenTypeJWT {
		f.t.Errorf("service exchange form = %v", r.PostForm)
	}
	if r.PostForm.Get("subject_token") != "identity-1" {
		f.t.Errorf("subject_token = %q", r.PostForm.Get("subject_token"))
	}
	f.proofClaims(r, "/servicetoken/exchange")
	f.writeToken(w, "service-"+strconv.Itoa(int(n)))
}

func (f *fakeServer) rpc(w http.ResponseWriter, r *http.Request) {
	f.rpcs.Add(1)
	auth := r.Header.Get("Authorization")
	if !strings.HasPrefix(auth, "Bearer service-") {
		f.t.Errorf("Authorization = %q", auth)
	}
	token := strings.TrimPrefix(auth, "Bearer ")
	sum := sha256.Sum256([]byte(token))
	if c := f.proofClaims(r, "/svc.Service/Method"); c != nil && c["ath"] != base64.RawURLEncoding.EncodeToString(sum[:]) {
		f.t.Errorf("rpc proof ath does not bind %q", token)
	}
	w.WriteHeader(http.StatusOK)
}

func newTestClient(t *testing.T, f *fakeServer) *http.Client {
	t.Helper()
	tr, err := NewTransport(Config{Endpoint: f.URL + "/", Key: testKey(t), Organization: "s2r:test:org:1", UserAgent: "test/1"})
	if err != nil {
		t.Fatal(err)
	}

	return &http.Client{Transport: tr}
}

func TestTransport_SignsRequests(t *testing.T) {
	t.Parallel()

	f := newFakeServer(t, 900)
	client := newTestClient(t, f)

	for range 3 {
		if status := mustPost(t, client, f.URL+"/svc.Service/Method"); status != http.StatusOK {
			t.Fatalf("status = %d", status)
		}
	}
	if f.identities.Load() != 1 || f.services.Load() != 1 || f.rpcs.Load() != 3 {
		t.Fatalf("exchanges = %d/%d, rpcs = %d; want one exchange for three requests", f.identities.Load(), f.services.Load(), f.rpcs.Load())
	}
}

func TestTransport_RefreshesBeforeExpiry(t *testing.T) {
	t.Parallel()

	f := newFakeServer(t, 60) // inside the refresh margin: every request re-exchanges
	client := newTestClient(t, f)

	mustPost(t, client, f.URL+"/svc.Service/Method")
	mustPost(t, client, f.URL+"/svc.Service/Method")
	if f.services.Load() != 2 {
		t.Fatalf("service exchanges = %d, want 2", f.services.Load())
	}
}

func TestTransport_SingleFlight(t *testing.T) {
	t.Parallel()

	f := newFakeServer(t, 900)
	client := newTestClient(t, f)

	var wg sync.WaitGroup
	for range 10 {
		wg.Go(func() {
			_, err := post(t, client, f.URL+"/svc.Service/Method")
			if err != nil {
				t.Error(err)
			}
		})
	}
	wg.Wait()
	if f.services.Load() != 1 {
		t.Fatalf("service exchanges = %d, want 1", f.services.Load())
	}
}

func TestTransport_Refusal(t *testing.T) {
	t.Parallel()

	for name, body := range map[string]string{
		"rfc 6749 body": `{"error":"invalid_grant","error_description":"The assertion's kid is unknown."}`,
		"server body":   `{"error":"invalid_grant","title":"Invalid Grant","message":"The assertion's kid is unknown."}`,
	} {
		t.Run(name, func(t *testing.T) {
			t.Parallel()

			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
				w.WriteHeader(http.StatusBadRequest)
				_, _ = w.Write([]byte(body))
			}))
			t.Cleanup(srv.Close)
			tr, err := NewTransport(Config{Endpoint: srv.URL, Key: testKey(t)})
			if err != nil {
				t.Fatal(err)
			}

			_, err = post(t, &http.Client{Transport: tr}, srv.URL+"/x")
			var refused *ExchangeError
			if !errors.As(err, &refused) {
				t.Fatalf("err = %v, want *ExchangeError", err)
			}
			if refused.Code != "invalid_grant" || refused.Description != "The assertion's kid is unknown." {
				t.Fatalf("refusal = %+v", refused)
			}
		})
	}
}

func TestExchangeError_OmitsAnEmptyReason(t *testing.T) {
	t.Parallel()

	got := (&ExchangeError{Status: 400, Code: "invalid_request"}).Error()
	if got != "the server refused the token exchange (invalid_request)" {
		t.Fatalf("Error() = %q", got)
	}
}

func TestNewTransport_Rejects(t *testing.T) {
	t.Parallel()

	_, err := NewTransport(Config{Endpoint: "api.example.com", Key: testKey(t)})
	if !errors.Is(err, ErrEndpoint) {
		t.Fatalf("relative endpoint: err = %v, want ErrEndpoint", err)
	}
	_, err = NewTransport(Config{Endpoint: "https://api.example.com"})
	if !errors.Is(err, ErrMissingKey) {
		t.Fatalf("missing key: err = %v, want ErrMissingKey", err)
	}
	_, err = NewTransport(Config{Endpoint: "https://api.example.com/v1", Key: testKey(t)})
	if !errors.Is(err, ErrEndpoint) {
		t.Fatalf("endpoint with a path: err = %v, want ErrEndpoint", err)
	}
}

func TestTransport_RefusesRedirectToAnotherHost(t *testing.T) {
	t.Parallel()

	var leaked atomic.Value
	other := httptest.NewServer(http.HandlerFunc(func(_ http.ResponseWriter, r *http.Request) {
		leaked.Store(r.Header.Get("Authorization"))
	}))
	t.Cleanup(other.Close)

	f := newFakeServer(t, 900)
	mux, ok := f.Config.Handler.(*http.ServeMux)
	if !ok {
		t.Fatal("the fake server does not use a ServeMux")
	}
	mux.HandleFunc("POST /redirect", func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+"/other", http.StatusTemporaryRedirect)
	})
	client := newTestClient(t, f)

	_, err := post(t, client, f.URL+"/redirect")
	if !errors.Is(err, ErrForeignHost) {
		t.Fatalf("err = %v, want ErrForeignHost", err)
	}
	if got := leaked.Load(); got != nil {
		t.Fatalf("another host received Authorization %q", got)
	}
}
