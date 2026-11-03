variable "aws_role_arn" {
  description = "IAM role the app signs in to, such as arn:aws:iam::123456789012:role/ops."
  type        = string
}

variable "aws_saml_provider_arn" {
  description = "IAM SAML provider that trusts the identity provider, such as arn:aws:iam::123456789012:saml-provider/splitsecure."
  type        = string
}

data "splitsecure_vault" "platform" {
  name = "platform"
}

resource "splitsecure_saml2_identity_provider" "aws_console" {
  vault_id = data.splitsecure_vault.platform.id
  name     = "platform-engineering/aws-123456789012"
}

resource "splitsecure_connected_app" "aws_ops" {
  issuer_vault_id = data.splitsecure_vault.platform.id
  issuer_id       = splitsecure_saml2_identity_provider.aws_console.id
  template        = "saml2/aws"

  name        = "aws-ops"
  description = "Sign in to the ops role of AWS account 123456789012."

  saml2 {
    entity_id = "urn:amazon:webservices"
    acs_url   = "https://signin.aws.amazon.com/saml"
  }

  field {
    name  = "role_arn"
    value = var.aws_role_arn
  }

  field {
    name  = "saml_provider_arn"
    value = var.aws_saml_provider_arn
  }

  field {
    name  = "name_id_format"
    value = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  }

  # The NameID is the requester's email.
  field {
    name      = "requester_email"
    requester = "email"
  }

  name_id {
    parts = ["field:requester_email"]
  }

  # Each sign-in chooses a session length within the range.
  field {
    name = "session_duration"
    duration_range {
      min_seconds     = 900
      max_seconds     = 3600
      default_seconds = 1800
    }
  }

  # Repeatable fields take a key: here, AWS session tags.
  field {
    name  = "session_tag"
    key   = "Team"
    value = "platform"
  }

  field {
    name      = "session_tag"
    key       = "Email"
    requester = "email"
  }

  justification = "Let platform engineering sign in to the AWS ops role"
  wait          = "30s"
}
