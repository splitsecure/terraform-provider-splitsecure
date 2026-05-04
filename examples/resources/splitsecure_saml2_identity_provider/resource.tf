resource "splitsecure_saml2_identity_provider" "aws_console" {
  team_s2r = "s2r:us:team:..."

  name        = "platform-engineering/aws-123456789012"
  description = "SAML IdP fronting AWS account 123456789012."
  # provider_id (SAML EntityID), sso_url, sso_url_post all default
  # server-side: the EntityID becomes a six-BIP39-word URL (matches
  # the web UI) and the SSO URLs anchor on the deployment's
  # frontend host. Set explicitly only for a stable URN-form EntityID
  # or a non-default SSO host.
}
