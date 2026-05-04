resource "splitsecure_saml2_service_provider" "aws_console" {
  team_s2r         = "s2r:<deployment>:team:01HX..."
  idp_resource_s2r = "s2r:<deployment>:saml2idp:01HX..."

  name                = "platform-engineering/aws-123456789012"
  description         = "Admin federation into AWS account 123456789012."
  notification_policy = "notify_everyone"
  sensitivity         = "high"
  entity_id           = "urn:amazon:webservices"
  # Plain IAM Federation ACS. For AWS Identity Center, paste the
  # per-instance "https://signin.aws.amazon.com/saml/acs/SAML<id>"
  # from the Identity Center metadata XML.
  acs_url = "https://signin.aws.amazon.com/saml"

  account {
    kind = "aws"
    aws {
      saml_provider_arn = "arn:aws:iam::123456789012:saml-provider/splitsecure"
      allowed_role_arns = ["arn:aws:iam::123456789012:role/SplitSecureAdmin"]
    }
  }
}
