data "splitsecure_vault" "platform" {
  name = "platform"
}

resource "splitsecure_oidc_issuer" "ci" {
  vault_id = data.splitsecure_vault.platform.id

  name        = "ci"
  description = "Issues identity tokens to CI workloads."

  # Leave algs unset for the default key set.
  algs = ["ES256", "EdDSA"]

  justification = "Issue workload identity tokens for CI"
  wait          = "30s"
}

output "ci_issuer" {
  value = splitsecure_oidc_issuer.ci.issuer
}
