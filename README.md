# Terraform Provider for SplitSecure

Terraform provider for managing SplitSecure SAML2 resources via service-account API keys. Each Create / Delete is a SplitSecure proposal: the provider builds the envelope server-side, sends it through the proposal-scoped managed enclave, and polls until voters approve and the resource record lands.

## Resources

- **`splitsecure_saml2_identity_provider`** — SAML IdP on a SplitSecure team. Computed `metadata_xml` is suitable as the `saml_metadata_document` input for `aws_iam_saml_provider`.
- **`splitsecure_saml2_service_provider`** — SAML SP bound to an IdP, supporting all 17 saml2v2 integration variants (AWS, Cloudflare, Okta, GCP, etc.).

Generated reference docs live in [`docs/`](./docs); per-resource attribute tables, validators, and example blocks are kept in sync via `tfplugindocs` (`make docs`).

## Authentication

1. Create a service account in the SplitSecure admin console.
2. Generate an API key — token format `s2ak_{keyId}_{principalId}_{secret}`.
3. Set `SPLITSECURE_BEARER_TOKEN` in the environment, or pass `bearer_token` in the provider HCL block.

## Installation (dev override)

```bash
make build
```

Then in `~/.terraformrc`:

```hcl
provider_installation {
  dev_overrides {
    "splitsecure/splitsecure" = "/path/to/terraform-provider-splitsecure"
  }
  direct {}
}
```

## Provider Configuration

```hcl
provider "splitsecure" {
  bearer_token = "s2ak_..."                # or SPLITSECURE_BEARER_TOKEN (the only secret)
  endpoint     = "https://..."             # or SPLITSECURE_ENDPOINT (defaults to production)
  org_s2r      = "s2r:<deployment>:org:<org_id>"  # required; or SPLITSECURE_ORG_S2R fallback
}
```

`org_s2r` is provider-scoped, not per-resource — it's only consumed by the proposal-scoped enclave spawn at Send time. Multi-org callers alias the provider.

## Example

End-to-end example covering two SplitSecure teams + admin + read-only AWS federations: [`examples/full/main.tf`](./examples/full/main.tf).

```bash
cd examples/full
cp terraform.tfvars.example terraform.tfvars  # fill in your s2r URIs (gitignored)
export SPLITSECURE_BEARER_TOKEN=s2ak_...
terraform plan
terraform apply -auto-approve
terraform destroy -auto-approve
```

## Development

### Proto sync

The provider ships an allowlisted subset of `.proto` definitions, plus three slim provider-owned services (so threshold/bottle/hybridkeyset transitive deps don't end up in the build).

```bash
./scripts/sync-protos.sh /path/to/source/apis/proto
buf generate
```

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
