# Terraform Provider for SplitSecure

Terraform provider for SplitSecure. It signs in as a service account and creates SAML and OIDC connected apps through the vault API. It also manages their identity providers, issuers, folders and grants. A create or a delete that needs team approval waits until the team approves it.

## Resources

- `splitsecure_saml2_identity_provider`: a SAML identity provider record. Its `metadata_xml` is the input for the cloud side, for example `aws_iam_saml_provider`.
- `splitsecure_oidc_issuer`: an OIDC issuer record. The cloud side trusts its issuer URL.
- `splitsecure_connected_app`: a SAML or OIDC connected app, built from a template. It exports `derived_values` for the cloud side.
- `splitsecure_vault_folder`: a folder in a vault.
- `splitsecure_vault_grant`: one grant on a vault folder or record.
- `splitsecure_vault_node_grants`: every direct grant on a vault folder or record.
- `splitsecure_group` and `splitsecure_group_member`: a local group of principals, and one member of it.
- `splitsecure_grant`: a grant on an org resource.

Data sources: `splitsecure_vault`, `splitsecure_organization`, `splitsecure_principal`, `splitsecure_org_member` and `splitsecure_group`.

The reference docs are in [`docs/`](./docs). `make docs` generates them with `tfplugindocs`.

## Authentication

The provider signs in as a service account. Use a key, or use workload identity. Setting both is an error.

### Key

1. Create a service account in the SplitSecure admin console.
2. Register a public key for it. ECDSA P-256, P-384, P-521 and Ed25519 are accepted, and RSA is refused. The console shows the key id.
3. Give the provider the account s2r, the key id and the private key. Use the HCL block, or the `SPLITSECURE_SERVICE_ACCOUNT_S2R`, `SPLITSECURE_KEY_ID` and `SPLITSECURE_PRIVATE_KEY` environment variables.

The provider signs a short assertion with the key, exchanges it for a service token and binds every request to a per-process DPoP key. The private key never leaves the machine.

### Workload identity

Workload identity signs in with an OIDC token from your CI system, so no long-lived key is stored. GitHub Actions is supported first.

1. Create a service account in the SplitSecure admin console.
2. Add a binding to the account that matches your workflow's token.
3. Add an empty `workload_identity` block to the provider and set `service_account_s2r`.
4. Give the job the `id-token: write` permission.

The provider asks GitHub for a new ID token on every refresh and sends it with the service account s2r. It never stores the token. To use a token from another source, set `workload_identity.token` or `SPLITSECURE_WORKLOAD_TOKEN`. The token's `aud` claim must be `https://monolith.us-east-2.aws.splitsecure.com`.

## Installation (dev override)

To test a local build against any plan, including the ones in `examples/`, use the `install-dev` target. You do not need to publish to the registry. The target builds the provider and writes `~/.terraformrc` with a `dev_overrides` block that points at the local binary. After that, every `terraform` command on this machine uses the local build for `splitsecure/splitsecure`.

```bash
make install-dev      # build + write ~/.terraformrc
make uninstall-dev    # remove ~/.terraformrc
```

`install-dev` refuses to overwrite a `~/.terraformrc` that it did not write. A marker comment identifies its own file. If you have your own file, back it up first.

## Provider Configuration

```hcl
provider "splitsecure" {
  service_account_s2r = "s2r:us:sa:<id>"       # or SPLITSECURE_SERVICE_ACCOUNT_S2R
  key_id              = "..."                  # or SPLITSECURE_KEY_ID
  private_key         = file("sa.pem")         # or SPLITSECURE_PRIVATE_KEY (the only secret)
  org_s2r             = "s2r:us:org:<org_id>"  # required; or SPLITSECURE_ORG_S2R fallback
}
```

With workload identity inside GitHub Actions, remove `key_id` and `private_key` and add an empty block:

```hcl
provider "splitsecure" {
  service_account_s2r = "s2r:us:sa:<id>"
  org_s2r             = "s2r:us:org:<org_id>"

  workload_identity {}
}
```

`workload_identity.token` (sensitive, or `SPLITSECURE_WORKLOAD_TOKEN`) overrides the GitHub token.

`org_s2r` is the org that the provider acts in. Vault lookups and groups use it. To manage more than one org, use one provider alias for each org.

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

The build writes `terraform-provider-splitsecure` and stamps the version from the `VERSION` file through `-ldflags`.

### Lint

```bash
make lint
```

### Docs

```bash
make docs        # regenerates docs/ via tfplugindocs
make check-docs  # regen + fail if there's a diff (matches the CI gate)
```

`go generate ./...`, wired through `main.go`, is the underlying entry point.

### Test

```bash
go test ./...                # unit tests
TF_ACC=1 go test ./...       # acceptance tests (no harness yet)
```
