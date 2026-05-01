package saml2

import (
	"context"
	"fmt"
	"net/mail"
	"net/url"
	"regexp"
	"strings"

	"github.com/hashicorp/terraform-plugin-framework-validators/stringvalidator"
	"github.com/hashicorp/terraform-plugin-framework/schema/validator"
)

// s2rKindValidator returns a schema-level validator that an attribute
// is an s2r URI of the given kind (`s2r:{deployment}:{kind}:...`).
// Catches "pasted the wrong URI" mistakes at `terraform plan` time
// instead of Send time. Deployment and identifier segments are
// unrestricted; only the scheme and kind slot are pinned.
func s2rKindValidator(kind string) validator.String {
	pattern := regexp.MustCompile(`^s2r:[^:]+:` + regexp.QuoteMeta(kind) + `:[^:]+$`)

	return stringvalidator.RegexMatches(
		pattern,
		`must be an s2r URI of kind "`+kind+`" (s2r:{deployment}:`+kind+`:...)`,
	)
}

// httpsURLValidator returns a validator that an attribute parses as
// an https:// URL via net/url. SAML2 SSO/ACS endpoints all sit behind
// TLS in practice; rejecting plaintext at plan time is less surprising
// than the server rejecting them mid-Send.
func httpsURLValidator() validator.String {
	return httpsURLVal{}
}

type httpsURLVal struct{}

func (httpsURLVal) Description(_ context.Context) string { return "must be an https:// URL" }

func (v httpsURLVal) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (httpsURLVal) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	raw := req.ConfigValue.ValueString()
	u, err := url.Parse(raw)
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid URL", fmt.Sprintf("%q is not a valid URL: %v", raw, err))

		return
	}
	if u.Scheme != "https" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid URL scheme", fmt.Sprintf("%q must be an https:// URL", raw))

		return
	}
	if u.Host == "" {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid URL", fmt.Sprintf("%q is missing a host", raw))
	}
}

// emailValidator returns a validator that an attribute parses as an
// RFC 5322 address via net/mail.ParseAddress. Catches typos at plan
// time without a hand-rolled regex.
func emailValidator() validator.String {
	return emailVal{}
}

type emailVal struct{}

func (emailVal) Description(_ context.Context) string {
	return "must be an email address (local@host.tld)"
}

func (v emailVal) MarkdownDescription(ctx context.Context) string {
	return v.Description(ctx)
}

func (emailVal) ValidateString(_ context.Context, req validator.StringRequest, resp *validator.StringResponse) {
	if req.ConfigValue.IsNull() || req.ConfigValue.IsUnknown() {
		return
	}
	raw := req.ConfigValue.ValueString()
	_, err := mail.ParseAddress(raw)
	if err != nil {
		resp.Diagnostics.AddAttributeError(req.Path, "Invalid email", fmt.Sprintf("%q is not a valid email address: %v", raw, err))
	}
}

// resourceS2RParts is the destructured form of an s2r resource URI.
// `s2r:{deployment}:{kind}:{team_id}/{resource_id}` -> {Deployment,
// Kind, TeamID, ResourceID}. Returned by parseResourceS2R; the
// helpers below use it to project back into related URIs (team URI,
// sibling-kind resource URI).
type resourceS2RParts struct {
	Deployment string
	Kind       string
	TeamID     string
	ResourceID string
}

// parseResourceS2R splits a resource URI into its four logical parts.
// The boolean is false for anything that doesn't match `s2r:{...}:
// {kind}:{team}/{resource}` so callers can no-op cleanly on legacy or
// malformed records.
func parseResourceS2R(resourceS2R string) (resourceS2RParts, bool) {
	parts := strings.SplitN(resourceS2R, ":", 4) //nolint:mnd // s2r is exactly four colon-segments.
	if len(parts) != 4 || parts[0] != "s2r" {
		return resourceS2RParts{}, false
	}
	team, resource, found := strings.Cut(parts[3], "/")
	if !found || team == "" || resource == "" {
		return resourceS2RParts{}, false
	}

	return resourceS2RParts{
		Deployment: parts[1],
		Kind:       parts[2],
		TeamID:     team,
		ResourceID: resource,
	}, true
}

// teamS2RFromResourceS2R reconstructs the team URI a resource lives
// on. Used on Read to backfill the resource model's team_s2r so a
// fresh import is plan-idempotent without state surgery.
func teamS2RFromResourceS2R(resourceS2R string) string {
	p, ok := parseResourceS2R(resourceS2R)
	if !ok {
		return ""
	}

	return "s2r:" + p.Deployment + ":team:" + p.TeamID
}
