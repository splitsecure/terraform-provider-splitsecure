package provider

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"maps"
	"strings"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/provider"
	"github.com/hashicorp/terraform-plugin-framework/tfsdk"
	"github.com/hashicorp/terraform-plugin-framework/types"
	"github.com/hashicorp/terraform-plugin-go/tftypes"

	"github.com/splitsecure/terraform-provider-splitsecure/splitsecure/client"
)

const testAccount = "s2r:us:sa:1"

var credentialEnvs = []string{
	"SPLITSECURE_SERVICE_ACCOUNT_S2R",
	"SPLITSECURE_KEY_ID",
	"SPLITSECURE_PRIVATE_KEY",
	"SPLITSECURE_WORKLOAD_TOKEN",
	"SPLITSECURE_ORG_S2R",
	"ACTIONS_ID_TOKEN_REQUEST_URL",
	"ACTIONS_ID_TOKEN_REQUEST_TOKEN",
}

func clearCredentialEnv(t *testing.T) {
	t.Helper()

	for _, name := range credentialEnvs {
		t.Setenv(name, "")
	}
}

func testPrivateKeyPEM(t *testing.T) string {
	t.Helper()

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	der, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}

	return string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: der}))
}

func TestConfigureCredential(t *testing.T) {
	keyPEM := testPrivateKeyPEM(t)

	cases := map[string]struct {
		env     map[string]string
		config  splitsecureProviderModel
		wantErr string
		wantKey bool
		// wantToken is what the workload token source returns, when set.
		wantToken string
		// wantSource reports that a workload token source is set whatever it returns.
		wantSource bool
	}{
		"key from config": {
			config: splitsecureProviderModel{
				ServiceAccountS2R: types.StringValue(testAccount),
				KeyID:             types.StringValue("kid"),
				PrivateKey:        types.StringValue(keyPEM),
			},
			wantKey: true,
		},
		"key from env": {
			env: map[string]string{
				"SPLITSECURE_SERVICE_ACCOUNT_S2R": testAccount,
				"SPLITSECURE_KEY_ID":              "kid",
				"SPLITSECURE_PRIVATE_KEY":         keyPEM,
			},
			wantKey: true,
		},
		"missing account": {
			config:  splitsecureProviderModel{KeyID: types.StringValue("kid"), PrivateKey: types.StringValue(keyPEM)},
			wantErr: "Missing service_account_s2r",
		},
		"missing key id and private key": {
			config:  splitsecureProviderModel{ServiceAccountS2R: types.StringValue(testAccount)},
			wantErr: "Missing key_id",
		},
		"invalid private key": {
			config: splitsecureProviderModel{
				ServiceAccountS2R: types.StringValue(testAccount),
				KeyID:             types.StringValue("kid"),
				PrivateKey:        types.StringValue("not pem"),
			},
			wantErr: "Invalid private_key",
		},
		"workload block with a key": {
			config: splitsecureProviderModel{
				ServiceAccountS2R: types.StringValue(testAccount),
				KeyID:             types.StringValue("kid"),
				WorkloadIdentity:  &workloadIdentityModel{Token: types.StringValue("tok")},
			},
			wantErr: "Conflicting credentials",
		},
		"workload block with a key from env": {
			env: map[string]string{"SPLITSECURE_PRIVATE_KEY": keyPEM},
			config: splitsecureProviderModel{
				ServiceAccountS2R: types.StringValue(testAccount),
				WorkloadIdentity:  &workloadIdentityModel{Token: types.StringValue("tok")},
			},
			wantErr: "Conflicting credentials",
		},
		"workload token from config": {
			config: splitsecureProviderModel{
				ServiceAccountS2R: types.StringValue(testAccount),
				WorkloadIdentity:  &workloadIdentityModel{Token: types.StringValue("tok")},
			},
			wantToken: "tok",
		},
		"workload without a token outside GitHub Actions": {
			config: splitsecureProviderModel{
				ServiceAccountS2R: types.StringValue(testAccount),
				WorkloadIdentity:  &workloadIdentityModel{},
			},
			wantErr: "No workload identity token",
		},
		"workload falls back to GitHub Actions": {
			env: map[string]string{ //nolint:gosec // a test value, not a credential.
				"ACTIONS_ID_TOKEN_REQUEST_URL":   "https://actions.example.com/token",
				"ACTIONS_ID_TOKEN_REQUEST_TOKEN": "runner",
			},
			config: splitsecureProviderModel{
				ServiceAccountS2R: types.StringValue(testAccount),
				WorkloadIdentity:  &workloadIdentityModel{},
			},
			wantSource: true,
		},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			clearCredentialEnv(t)

			for k, v := range tc.env {
				t.Setenv(k, v)
			}

			var (
				cfg   client.Config
				diags diag.Diagnostics
			)

			ok := (&splitsecureProvider{}).configureCredential(&tc.config, &cfg, &diags)

			if tc.wantErr != "" {
				if ok || !hasErrorSummary(diags, tc.wantErr) {
					t.Fatalf("ok = %v, diags = %v, want %q", ok, diags, tc.wantErr)
				}

				return
			}

			if !ok || diags.HasError() {
				t.Fatalf("ok = %v, diags = %v", ok, diags)
			}

			assertCredential(t, &cfg, tc.wantKey, tc.wantSource, tc.wantToken)
		})
	}
}

func assertCredential(t *testing.T, cfg *client.Config, wantKey, wantSource bool, wantToken string) {
	t.Helper()

	if (cfg.Key != nil) != wantKey {
		t.Errorf("key set = %v, want %v", cfg.Key != nil, wantKey)
	}

	if wantToken != "" {
		token, err := cfg.Workload.TokenSource(context.Background(), "aud")
		if err != nil || token != wantToken {
			t.Errorf("token = %q, err = %v, want %q", token, err, wantToken)
		}

		return
	}

	if (cfg.Workload != nil) != wantSource {
		t.Errorf("workload set = %v, want %v", cfg.Workload != nil, wantSource)
	}
}

func TestConfigureWorkload_ReadsTheEnvTokenOnEveryCall(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv("SPLITSECURE_WORKLOAD_TOKEN", "first")

	var (
		cfg   client.Config
		diags diag.Diagnostics
	)

	if !(&splitsecureProvider{}).configureWorkload(&workloadIdentityModel{}, testAccount, &cfg, &diags) {
		t.Fatalf("diags = %v", diags)
	}

	t.Setenv("SPLITSECURE_WORKLOAD_TOKEN", "second")

	token, err := cfg.Workload.TokenSource(context.Background(), "aud")
	if err != nil || token != "second" {
		t.Fatalf("token = %q, err = %v, want the current env value", token, err)
	}
}

func hasErrorSummary(diags diag.Diagnostics, want string) bool {
	for _, d := range diags.Errors() {
		if strings.Contains(d.Summary(), want) {
			return true
		}
	}

	return false
}

func TestValueOrEnv(t *testing.T) {
	t.Setenv("SPLITSECURE_TEST_VALUE", "from-env")

	cases := map[string]struct {
		value types.String
		want  string
	}{
		"config wins":         {types.StringValue("literal"), "literal"},
		"null falls back":     {types.StringNull(), "from-env"},
		"empty falls back":    {types.StringValue(""), "from-env"},
		"unknown never falls": {types.StringUnknown(), ""},
	}

	for name, tc := range cases {
		if got := valueOrEnv(tc.value, "SPLITSECURE_TEST_VALUE"); got != tc.want {
			t.Errorf("%s: valueOrEnv = %q, want %q", name, got, tc.want)
		}
	}
}

func configureWith(t *testing.T, attrs map[string]tftypes.Value, token tftypes.Value) provider.ConfigureResponse {
	t.Helper()

	p := &splitsecureProvider{version: "test"}

	var sresp provider.SchemaResponse
	p.Schema(context.Background(), provider.SchemaRequest{}, &sresp)

	objType, ok := sresp.Schema.Type().TerraformType(context.Background()).(tftypes.Object)
	if !ok {
		t.Fatal("the schema is not an object")
	}

	wlType, ok := objType.AttributeTypes["workload_identity"].(tftypes.Object)
	if !ok {
		t.Fatal("workload_identity is not an object")
	}

	values := map[string]tftypes.Value{
		"org_s2r":             tftypes.NewValue(tftypes.String, nil),
		"service_account_s2r": tftypes.NewValue(tftypes.String, testAccount),
		"key_id":              tftypes.NewValue(tftypes.String, nil),
		"private_key":         tftypes.NewValue(tftypes.String, nil),
		"workload_identity":   tftypes.NewValue(wlType, map[string]tftypes.Value{"token": token}),
	}
	maps.Copy(values, attrs)

	var resp provider.ConfigureResponse

	p.Configure(context.Background(), provider.ConfigureRequest{Config: tfsdk.Config{Raw: tftypes.NewValue(objType, values), Schema: sresp.Schema}}, &resp)

	return resp
}

func TestConfigure_RefusesUnknownValues(t *testing.T) {
	cases := map[string]struct {
		attrs map[string]tftypes.Value
		token tftypes.Value
	}{
		"org_s2r":             {attrs: map[string]tftypes.Value{"org_s2r": tftypes.NewValue(tftypes.String, tftypes.UnknownValue)}, token: tftypes.NewValue(tftypes.String, nil)},
		"service_account_s2r": {attrs: map[string]tftypes.Value{"service_account_s2r": tftypes.NewValue(tftypes.String, tftypes.UnknownValue)}, token: tftypes.NewValue(tftypes.String, nil)},
		"key_id":              {attrs: map[string]tftypes.Value{"key_id": tftypes.NewValue(tftypes.String, tftypes.UnknownValue)}, token: tftypes.NewValue(tftypes.String, nil)},
		"private_key":         {attrs: map[string]tftypes.Value{"private_key": tftypes.NewValue(tftypes.String, tftypes.UnknownValue)}, token: tftypes.NewValue(tftypes.String, nil)},
		"workload token":      {token: tftypes.NewValue(tftypes.String, tftypes.UnknownValue)},
	}

	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			clearCredentialEnv(t)
			t.Setenv("SPLITSECURE_ORG_S2R", "s2r:us:org:from-env")
			t.Setenv("SPLITSECURE_KEY_ID", "kid-from-env")
			t.Setenv("SPLITSECURE_PRIVATE_KEY", testPrivateKeyPEM(t))
			t.Setenv("SPLITSECURE_WORKLOAD_TOKEN", "tok")

			resp := configureWith(t, tc.attrs, tc.token)
			if !hasErrorSummary(resp.Diagnostics, "Unknown") || resp.ResourceData != nil {
				t.Fatalf("diags = %v, data = %v, want an unknown-value error and no client", resp.Diagnostics, resp.ResourceData)
			}
		})
	}
}

func TestConfigure_KnownOrgFromEnvConfigures(t *testing.T) {
	clearCredentialEnv(t)
	t.Setenv("SPLITSECURE_ORG_S2R", "s2r:us:org:from-env")

	resp := configureWith(t, nil, tftypes.NewValue(tftypes.String, "tok"))
	if resp.Diagnostics.HasError() {
		t.Fatalf("diags = %v", resp.Diagnostics)
	}

	if c, ok := resp.ResourceData.(*client.Client); !ok || c.OrgS2R != "s2r:us:org:from-env" {
		t.Fatalf("resource data = %v", resp.ResourceData)
	}
}
