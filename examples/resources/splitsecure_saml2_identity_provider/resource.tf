resource "splitsecure_saml2_identity_provider" "aws_console" {
  team_s2r = "s2r:us:team:..."

  name        = "platform-engineering/aws-123456789012"
  description = "SAML IdP fronting AWS account 123456789012."
  # provider_id (SAML EntityID) defaults to a six-BIP39-word URL
  # (matches the web UI). Set explicitly for a stable URN-form
  # EntityID. sso_url_redirect and sso_url_post are server-assigned
  # (read-only) and anchor on the deployment's frontend host.
}
