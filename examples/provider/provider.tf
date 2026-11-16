# Sign in as a service account with a key registered on it.
# Each setting falls back to its SPLITSECURE_ environment variable,
# so the private key can stay out of the configuration.
provider "splitsecure" {
  org_s2r             = var.org_s2r
  service_account_s2r = var.service_account_s2r
  key_id              = var.key_id
  # private_key is read from SPLITSECURE_PRIVATE_KEY.
}

# Inside GitHub Actions, sign in with the job's ID token instead of a key.
# The job needs the id-token: write permission, and the service account
# needs a binding that matches the token.
provider "splitsecure" {
  alias               = "github_actions"
  org_s2r             = var.org_s2r
  service_account_s2r = var.service_account_s2r

  workload_identity {}
}
