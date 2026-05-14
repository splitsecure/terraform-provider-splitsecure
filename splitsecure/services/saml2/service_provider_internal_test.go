package saml2

import (
	"context"
	"slices"
	"testing"

	"github.com/hashicorp/terraform-plugin-framework/diag"
	"github.com/hashicorp/terraform-plugin-framework/types"

	saml2v2 "github.com/splitsecure/apis/gen/go/proto/splitsecure/saml2/v2"
)

// accountVariantFixtures returns one synthetic accountModel per
// supported SP variant. Each entry carries a non-zero value in every
// field that the variant exposes so a round-trip catches any field
// the encoder / decoder forgets.
func accountVariantFixtures(t *testing.T) map[string]*accountModel {
	t.Helper()

	listOf := func(vals ...string) types.List {
		l, d := types.ListValueFrom(context.Background(), types.StringType, vals)
		if d.HasError() {
			t.Fatalf("listOf: %v", d)
		}

		return l
	}

	return map[string]*accountModel{
		kindAWS: {
			Kind: types.StringValue(kindAWS),
			AWS: &accountAWSModel{
				SAMLProviderARN: types.StringValue("arn:aws:iam::123456789012:saml-provider/foo"),
				AllowedRoleARNs: listOf("arn:aws:iam::123456789012:role/r1", "arn:aws:iam::123456789012:role/r2"),
			},
		},
		kindCloudflare: {
			Kind: types.StringValue(kindCloudflare),
			Cloudflare: &accountCloudflareModel{
				SSOEndpoint:  types.StringValue("https://example.cloudflareaccess.com"),
				DefaultEmail: types.StringValue("ops@example.com"),
			},
		},
		kindEventBrite: {Kind: types.StringValue(kindEventBrite), EventBrite: &accountEventBriteModel{}},
		kindGCP: {
			Kind: types.StringValue(kindGCP),
			GCP:  &accountGCPModel{DefaultEmail: types.StringValue("ops@example.com")},
		},
		kindGoogleWorkspace: {
			Kind:            types.StringValue(kindGoogleWorkspace),
			GoogleWorkspace: &accountGoogleWorkspaceModel{},
		},
		kindGoogleWorkspaceLegacy: {
			Kind: types.StringValue(kindGoogleWorkspaceLegacy),
			GoogleWorkspaceLegacy: &accountGoogleWorkspaceLegacyModel{
				DefaultEmail: types.StringValue("ops@example.com"),
				DomainName:   types.StringValue("example.com"),
			},
		},
		kindIBMCloud: {
			Kind:     types.StringValue(kindIBMCloud),
			IBMCloud: &accountIBMCloudModel{LoginURL: types.StringValue("https://cloud.ibm.com/login")},
		},
		kindKandji: {
			Kind:   types.StringValue(kindKandji),
			Kandji: &accountKandjiModel{DefaultEmail: types.StringValue("ops@example.com")},
		},
		kindMicrosoftEntraID: {
			Kind:             types.StringValue(kindMicrosoftEntraID),
			MicrosoftEntraID: &accountMicrosoftEntraIDModel{},
		},
		kindOkta: {
			Kind: types.StringValue(kindOkta),
			Okta: &accountOktaModel{AllowedEmails: listOf("a@example.com", "b@example.com")},
		},
		kindOracleCloud: {Kind: types.StringValue(kindOracleCloud), OracleCloud: &accountOracleCloudModel{}},
		kindPagerDuty:   {Kind: types.StringValue(kindPagerDuty), PagerDuty: &accountPagerDutyModel{}},
		kindPitchBook:   {Kind: types.StringValue(kindPitchBook), PitchBook: &accountPitchBookModel{}},
		kindRapid7: {
			Kind: types.StringValue(kindRapid7),
			Rapid7: &accountRapid7Model{
				DefaultRelayState: types.StringValue("https://app/start"),
				DefaultEmail:      types.StringValue("ops@example.com"),
				DefaultFirstName:  types.StringValue("Ops"),
				DefaultLastName:   types.StringValue("Team"),
				DefaultRBACGroups: listOf("admins", "auditors"),
			},
		},
		kindStripe: {
			Kind:   types.StringValue(kindStripe),
			Stripe: &accountStripeModel{AccountID: types.StringValue("acct_123")},
		},
		kindVeeam:   {Kind: types.StringValue(kindVeeam), Veeam: &accountVeeamModel{}},
		kindWorkday: {Kind: types.StringValue(kindWorkday), Workday: &accountWorkdayModel{}},
	}
}

// TestSPAccountVariantsCovered asserts every kind in spAccountKinds
// has both a fixture and a round-trip case below. Catches the "added
// a new variant, forgot to update the test table" mistake.
func TestSPAccountVariantsCovered(t *testing.T) {
	t.Parallel()

	fixtures := accountVariantFixtures(t)
	for _, k := range spAccountKinds() {
		if _, ok := fixtures[k]; !ok {
			t.Fatalf("kind %q has no fixture in accountVariantFixtures -- update the test table", k)
		}
	}
	for k := range fixtures {
		if !slices.Contains(spAccountKinds(), k) {
			t.Fatalf("fixture %q is not in spAccountKinds() -- stale test entry", k)
		}
	}
}

// TestSPAccountRoundTrip exercises every variant through the full
// HCL-plan -> KnownProvider union -> HCL-plan loop, so a per-variant
// encoder/decoder mismatch (wrong wrapper type, missing field)
// surfaces here instead of mid-Send.
func TestSPAccountRoundTrip(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	for kind, original := range accountVariantFixtures(t) {
		t.Run(kind, func(t *testing.T) {
			t.Parallel()

			plan := &saml2ServiceProviderModel{Account: original}
			sp := &saml2v2.SAML2ServiceProvider{}
			gotKind, diags := setKnownProviderOnSP(ctx, sp, plan)
			if diags.HasError() {
				t.Fatalf("setKnownProviderOnSP: %v", diags)
			}
			if gotKind != kind {
				t.Fatalf("setKnownProviderOnSP returned kind %q, want %q", gotKind, kind)
			}
			if sp.GetKnownProvider().GetUnion() == nil {
				t.Fatalf("setKnownProviderOnSP left sp.KnownProvider.Union nil for kind %q", kind)
			}

			var rtDiags diag.Diagnostics
			got, gotBackKind := accountFromSP(ctx, sp, &rtDiags)
			if rtDiags.HasError() {
				t.Fatalf("accountFromSP: %v", rtDiags)
			}
			if gotBackKind != kind {
				t.Fatalf("accountFromSP returned kind %q, want %q", gotBackKind, kind)
			}
			assertAccountModelsEqual(t, original, got)
		})
	}
}

// assertAccountModelsEqual compares two *accountModel by walking the
// per-variant sub-block. types.String / types.List don't implement
// reflect.DeepEqual cleanly across framework versions, so use the
// framework's own .Equal where possible.
//
//nolint:cyclop // 17 branches mirror the SP account variants.
func assertAccountModelsEqual(t *testing.T, want, got *accountModel) {
	t.Helper()

	if !want.Kind.Equal(got.Kind) {
		t.Fatalf("kind: want %q, got %q", want.Kind.ValueString(), got.Kind.ValueString())
	}

	switch want.Kind.ValueString() {
	case kindAWS:
		assertStringEqual(t, "saml_provider_arn", want.AWS.SAMLProviderARN, got.AWS.SAMLProviderARN)
		assertListEqual(t, "allowed_role_arns", want.AWS.AllowedRoleARNs, got.AWS.AllowedRoleARNs)
	case kindCloudflare:
		assertStringEqual(t, "sso_endpoint", want.Cloudflare.SSOEndpoint, got.Cloudflare.SSOEndpoint)
		assertStringEqual(t, "default_email", want.Cloudflare.DefaultEmail, got.Cloudflare.DefaultEmail)
	case kindEventBrite:
		// no fields
	case kindGCP:
		assertStringEqual(t, "default_email", want.GCP.DefaultEmail, got.GCP.DefaultEmail)
	case kindGoogleWorkspace:
		// no fields
	case kindGoogleWorkspaceLegacy:
		assertStringEqual(t, "default_email", want.GoogleWorkspaceLegacy.DefaultEmail, got.GoogleWorkspaceLegacy.DefaultEmail)
		assertStringEqual(t, "domain_name", want.GoogleWorkspaceLegacy.DomainName, got.GoogleWorkspaceLegacy.DomainName)
	case kindIBMCloud:
		assertStringEqual(t, "login_url", want.IBMCloud.LoginURL, got.IBMCloud.LoginURL)
	case kindKandji:
		assertStringEqual(t, "default_email", want.Kandji.DefaultEmail, got.Kandji.DefaultEmail)
	case kindMicrosoftEntraID:
		// no fields
	case kindOkta:
		assertListEqual(t, "allowed_emails", want.Okta.AllowedEmails, got.Okta.AllowedEmails)
	case kindOracleCloud, kindPagerDuty, kindPitchBook, kindVeeam, kindWorkday:
		// empty types
	case kindRapid7:
		assertStringEqual(t, "default_relay_state", want.Rapid7.DefaultRelayState, got.Rapid7.DefaultRelayState)
		assertStringEqual(t, "default_email", want.Rapid7.DefaultEmail, got.Rapid7.DefaultEmail)
		assertStringEqual(t, "default_first_name", want.Rapid7.DefaultFirstName, got.Rapid7.DefaultFirstName)
		assertStringEqual(t, "default_last_name", want.Rapid7.DefaultLastName, got.Rapid7.DefaultLastName)
		assertListEqual(t, "default_rbac_groups", want.Rapid7.DefaultRBACGroups, got.Rapid7.DefaultRBACGroups)
	case kindStripe:
		assertStringEqual(t, "account_id", want.Stripe.AccountID, got.Stripe.AccountID)
	default:
		t.Fatalf("unknown kind %q in test comparator", want.Kind.ValueString())
	}
}

func assertStringEqual(t *testing.T, label string, want, got types.String) {
	t.Helper()

	if !want.Equal(got) {
		t.Fatalf("%s: want %q, got %q", label, want.ValueString(), got.ValueString())
	}
}

func assertListEqual(t *testing.T, label string, want, got types.List) {
	t.Helper()

	if !want.Equal(got) {
		t.Fatalf("%s: lists differ -- want %v, got %v", label, want, got)
	}
}
