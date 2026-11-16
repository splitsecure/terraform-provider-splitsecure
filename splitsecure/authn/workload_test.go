package authn

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strconv"
	"sync/atomic"
	"testing"
)

var errTokenSource = errors.New("token source down")

// workloadServer accepts the token-exchange grant on the first hop and
// answers the second hop like the key arm's fake does.
type workloadServer struct {
	*fakeServer

	subjects chan string
}

func newWorkloadServer(t *testing.T, expiresIn int) *workloadServer {
	t.Helper()
	f := &fakeServer{t: t, expiresIn: expiresIn}
	w := &workloadServer{fakeServer: f, subjects: make(chan string, 16)}
	mux := http.NewServeMux()
	mux.HandleFunc("POST /authn/exchange", w.identityExchange)
	mux.HandleFunc("POST /servicetoken/exchange", func(rw http.ResponseWriter, r *http.Request) {
		n := f.services.Add(1)
		f.proofClaims(r, "/servicetoken/exchange")
		f.writeToken(rw, "service-"+strconv.Itoa(int(n)))
	})
	mux.HandleFunc("POST /svc.Service/Method", f.rpc)
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Close)

	return w
}

func (w *workloadServer) identityExchange(rw http.ResponseWriter, r *http.Request) {
	w.identities.Add(1)
	_ = r.ParseForm()
	want := map[string]string{
		"grant_type":         grantTokenExchange,
		"subject_token_type": tokenTypeJWT,
		"service_account":    testAccount,
		"organization":       "s2r:test:org:1",
		"audience":           w.URL,
	}
	for k, v := range want {
		if got := r.PostForm.Get(k); got != v {
			w.t.Errorf("%s = %q, want %q", k, got, v)
		}
	}
	w.subjects <- r.PostForm.Get("subject_token")
	if c := w.proofClaims(r, "/authn/exchange"); c != nil && c["ath"] != nil {
		w.t.Error("identity exchange proof carries ath")
	}
	w.writeToken(rw, "identity-1")
}

func workloadClient(t *testing.T, w *workloadServer, source TokenSource) *http.Client {
	t.Helper()
	tr, err := NewTransport(Config{
		Endpoint:     w.URL,
		Workload:     &Workload{ServiceAccountS2R: testAccount, TokenSource: source},
		Organization: "s2r:test:org:1",
	})
	if err != nil {
		t.Fatal(err)
	}

	return &http.Client{Transport: tr}
}

func TestWorkload_ExchangesExternalToken(t *testing.T) {
	t.Parallel()

	w := newWorkloadServer(t, 900)
	var audience atomic.Value
	client := workloadClient(t, w, func(_ context.Context, aud string) (string, error) {
		audience.Store(aud)

		return "external-1", nil
	})

	if status := mustPost(t, client, w.URL+"/svc.Service/Method"); status != http.StatusOK {
		t.Fatalf("status = %d", status)
	}
	if got := <-w.subjects; got != "external-1" {
		t.Fatalf("subject_token = %q", got)
	}
	if got := audience.Load(); got != w.URL+"/authn" {
		t.Fatalf("token source audience = %v, want %s", got, w.URL+"/authn")
	}
}

func TestWorkload_RefreshFetchesFreshToken(t *testing.T) {
	t.Parallel()

	w := newWorkloadServer(t, 60) // inside the refresh margin: every request re-exchanges
	var calls atomic.Int32
	client := workloadClient(t, w, func(context.Context, string) (string, error) {
		return "external-" + strconv.Itoa(int(calls.Add(1))), nil
	})

	mustPost(t, client, w.URL+"/svc.Service/Method")
	mustPost(t, client, w.URL+"/svc.Service/Method")
	if calls.Load() != 2 {
		t.Fatalf("token source calls = %d, want 2", calls.Load())
	}
	first, second := <-w.subjects, <-w.subjects
	if first != "external-1" || second != "external-2" {
		t.Fatalf("subject tokens = %q, %q", first, second)
	}
}

func TestWorkload_TokenSourceError(t *testing.T) {
	t.Parallel()

	w := newWorkloadServer(t, 900)
	client := workloadClient(t, w, func(context.Context, string) (string, error) { return "", errTokenSource })

	_, err := post(t, client, w.URL+"/svc.Service/Method")
	if !errors.Is(err, errTokenSource) {
		t.Fatalf("err = %v, want errTokenSource", err)
	}
	if w.identities.Load() != 0 {
		t.Fatal("the exchange ran without a token")
	}
}

func TestWorkload_RejectsEmptyToken(t *testing.T) {
	t.Parallel()

	w := newWorkloadServer(t, 900)
	client := workloadClient(t, w, func(context.Context, string) (string, error) { return "", nil })

	_, err := post(t, client, w.URL+"/svc.Service/Method")
	if !errors.Is(err, ErrEmptyWorkloadToken) {
		t.Fatalf("err = %v, want ErrEmptyWorkloadToken", err)
	}
}

func TestNewTransport_RejectsCredentialMix(t *testing.T) {
	t.Parallel()

	source := func(context.Context, string) (string, error) { return "x", nil }
	workload := &Workload{ServiceAccountS2R: testAccount, TokenSource: source}

	_, err := NewTransport(Config{Endpoint: "https://api.example.com", Key: testKey(t), Workload: workload})
	if !errors.Is(err, ErrAmbiguousCredential) {
		t.Fatalf("both set: err = %v, want ErrAmbiguousCredential", err)
	}
	_, err = NewTransport(Config{Endpoint: "https://api.example.com"})
	if !errors.Is(err, ErrMissingKey) {
		t.Fatalf("neither set: err = %v, want ErrMissingKey", err)
	}
}

func TestWorkload_RejectsIncomplete(t *testing.T) {
	t.Parallel()

	source := func(context.Context, string) (string, error) { return "x", nil }
	cases := map[string]struct {
		workload Workload
		want     error
	}{
		"no account": {Workload{TokenSource: source}, ErrMissingAccount},
		"no source":  {Workload{ServiceAccountS2R: testAccount}, ErrMissingTokenSource},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			_, err := workloadCredential{workload: &tc.workload, issuer: "https://api.example.com/authn"}.firstHopForm(context.Background(), "https://api.example.com")
			if !errors.Is(err, tc.want) {
				t.Fatalf("err = %v, want %v", err, tc.want)
			}
		})
	}
}

func TestWorkload_FormCarriesIdentityAudienceAndTokenSourceGetsIssuer(t *testing.T) {
	t.Parallel()

	var asked string
	cred := workloadCredential{
		workload: &Workload{
			ServiceAccountS2R: testAccount,
			TokenSource: func(_ context.Context, aud string) (string, error) {
				asked = aud

				return "external", nil
			},
		},
		issuer: "https://api.example.com/authn",
	}

	form, err := cred.firstHopForm(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if got := form.Get("audience"); got != "https://api.example.com" {
		t.Errorf("audience = %q, want https://api.example.com", got)
	}
	if asked != "https://api.example.com/authn" {
		t.Errorf("token source audience = %q, want https://api.example.com/authn", asked)
	}
}

func TestGitHubActionsTokenSource(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if got := r.URL.Query().Get("audience"); got != "https://api.example.com" {
			t.Errorf("audience = %q", got)
		}
		if got := r.URL.Query().Get("keep"); got != "1" {
			t.Errorf("existing query dropped: %q", r.URL.RawQuery)
		}
		if got := r.Header.Get("Authorization"); got != "bearer request-token" {
			t.Errorf("Authorization = %q", got)
		}
		_ = json.NewEncoder(w).Encode(map[string]string{"value": "gh-jwt"})
	}))
	t.Cleanup(srv.Close)
	t.Setenv(githubRequestURLEnv, srv.URL+"/token?keep=1")
	t.Setenv(githubRequestTokenEnv, "request-token")

	source, err := GitHubActionsTokenSource(srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	token, err := source(context.Background(), "https://api.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if token != "gh-jwt" {
		t.Fatalf("token = %q", token)
	}
}

func TestGitHubActionsTokenSource_MissingEnv(t *testing.T) {
	t.Setenv(githubRequestURLEnv, "")
	t.Setenv(githubRequestTokenEnv, "")

	_, err := GitHubActionsTokenSource(nil)
	if !errors.Is(err, ErrNotGitHubActions) {
		t.Fatalf("err = %v, want ErrNotGitHubActions", err)
	}
}

func TestGitHubActionsTokenSource_Refusal(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	t.Cleanup(srv.Close)
	t.Setenv(githubRequestURLEnv, srv.URL)
	t.Setenv(githubRequestTokenEnv, "request-token")

	source, err := GitHubActionsTokenSource(srv.Client())
	if err != nil {
		t.Fatal(err)
	}
	_, err = source(context.Background(), "aud")
	if !errors.Is(err, ErrGitHubToken) {
		t.Fatalf("err = %v, want ErrGitHubToken", err)
	}
}
