# Terraform Provider for SplitSecure

Terraform provider for managing SplitSecure SAML2 resources via service-account API keys. Each Create / Delete is a SplitSecure proposal: the provider builds the envelope server-side, sends it through the proposal-scoped managed enclave, and polls until voters approve and the resource record lands.

## Resources

- **`splitsecure_saml2_identity_provider`** — SAML IdP on a SplitSecure team. Computed `metadata_xml` is suitable as the `saml_metadata_document` input for `aws_iam_saml_provider`.
- **`splitsecure_saml2_service_provider`** — SAML SP bound to an IdP, supporting all 17 saml2v2 integration variants (AWS, Cloudflare, Okta, GCP, etc.).
- **`splitsecure_grant`** — per-resource permission grant `(resource, grantee) → view/use/edit` so the resources above are visible/usable to org members, not just their creator. Plain RPCs, not proposal-gated. Tiers control visibility and permission management; resource mutations stay proposal/voter-gated regardless of tier.
- **`splitsecure_group`** — locally-managed principal group with an authoritative member list, used as a grant target. Group mutations require the provider's service account to hold the org **admin** role; grants alone work with the default member role (the creating service account receives `edit` on resources it creates).

Data sources: **`splitsecure_organization`** (org info incl. the "Everyone" group S2R for org-wide grants), **`splitsecure_principal`** (principal S2R by console email — resolves both users and service accounts), **`splitsecure_org_member`** (user S2R by email), **`splitsecure_group`** (existing group by its `group_s2r`).

Generated reference docs live in [`docs/`](./docs); per-resource attribute tables, validators, and example blocks are kept in sync via `tfplugindocs` (`make docs`).

## Authentication

The provider signs in as a service account. Use a key, or use workload identity. Setting both is an error.

### Key

1. Create a service account in the SplitSecure admin console.
2. Register a public key for it (ECDSA P-256, P-384, P-521 or Ed25519; RSA is refused). The console shows the key id.
3. Give the provider the account s2r, the key id and the private key, through the HCL block or the `SPLITSECURE_SERVICE_ACCOUNT_S2R`, `SPLITSECURE_KEY_ID` and `SPLITSECURE_PRIVATE_KEY` environment variables.

The provider signs a short assertion with the key, exchanges it for a service token and binds every request to a per-process DPoP key. The private key never leaves the machine.

### Workload identity

Workload identity signs in with an OIDC token from your CI system, so no long-lived key is stored. GitHub Actions is supported first.

1. Create a service account in the SplitSecure admin console.
2. Add a binding to the account that matches your workflow's token.
3. Add an empty `workload_identity` block to the provider and set `service_account_s2r`.
4. Give the job the `id-token: write` permission.

The provider asks GitHub for a new ID token on every refresh and sends it with the service account s2r. It never stores the token. To use a token from another source, set `workload_identity.token` or `SPLITSECURE_WORKLOAD_TOKEN`. The token's `aud` claim must be the endpoint's origin, for example `https://monolith.us-east-2.aws.splitsecure.com`.

## Installation (dev override)

To test a local build against any plan (including the ones in `examples/`) without
publishing to the registry, use the one-off install target. It builds the
provider and writes `~/.terraformrc` with a `dev_overrides` block pointing
at the local binary; from then on every `terraform` invocation on this
machine uses the local build for `splitsecure/splitsecure`:

```bash
make install-dev      # build + write ~/.terraformrc
make uninstall-dev    # remove ~/.terraformrc
```

`install-dev` refuses to clobber an existing `~/.terraformrc` it didn't
write (detected via a marker comment); back it up first if you have one.

## Provider Configuration

```hcl
provider "splitsecure" {
  service_account_s2r = "s2r:<deployment>:sa:<id>"   # or SPLITSECURE_SERVICE_ACCOUNT_S2R
  key_id              = "..."                         # or SPLITSECURE_KEY_ID
  private_key         = file("sa.pem")                # or SPLITSECURE_PRIVATE_KEY (the only secret)
  endpoint            = "https://..."                 # or SPLITSECURE_ENDPOINT (defaults to production)
  org_s2r             = "s2r:<deployment>:org:<org_id>"  # required; or SPLITSECURE_ORG_S2R fallback
}
```

With workload identity inside GitHub Actions, drop `key_id` and `private_key` and add an empty block:

```hcl
provider "splitsecure" {
  service_account_s2r = "s2r:<deployment>:sa:<id>"
  org_s2r             = "s2r:<deployment>:org:<org_id>"

  workload_identity {}
}
```


`workload_identity.token` (sensitive, or `SPLITSECURE_WORKLOAD_TOKEN`) overrides the GitHub token.

`org_s2r` is provider-scoped, not per-resource — it's only consumed by the proposal-scoped enclave spawn at Send time. Multi-org callers alias the provider.

## Examples

Each example creates a working cloud sign-in, both the SplitSecure and the cloud side. Its README says what to set and in what order.

- [`examples/aws-saml`](./examples/aws-saml): sign in to an AWS role with SAML.
- [`examples/aws-oidc`](./examples/aws-oidc): get AWS role sessions with OIDC tokens.
- [`examples/gcp-saml`](./examples/gcp-saml): sign in to the Google Cloud console with SAML, through a workforce pool.
- [`examples/gcp-oidc`](./examples/gcp-oidc): get Google Cloud service account tokens with OIDC tokens.
- [`examples/azure-saml`](./examples/azure-saml): sign in to Entra ID as a user of a federated domain with SAML.
- [`examples/azure-oidc`](./examples/azure-oidc): get Entra ID application tokens with OIDC tokens.

## Development

### Build

```bash
make build
```

Produces `terraform-provider-splitsecure` with a CalVer version (`1.YYMMDD.PATCH`) baked in via `-ldflags`.

### Lint

```bash
make lint
```

### Docs

```bash
make docs        # regenerates docs/ via tfplugindocs
make check-docs  # regen + fail if there's a diff (matches the CI gate)
```

`go generate ./...` (wired through `main.go`) is the underlying entry point.

### Test

```bash
go test ./...                # unit-mode smoke test
TF_ACC=1 go test ./...       # acceptance tests (deferred -- harness pending)
```
