terraform {
  required_version = ">= 1.11"

  required_providers {
    splitsecure = {
      source = "splitsecure/splitsecure"
    }
    aws = {
      source  = "hashicorp/aws"
      version = ">= 5.0"
    }
  }
}

# Reads SPLITSECURE_ORG_S2R, SPLITSECURE_SERVICE_ACCOUNT_S2R, SPLITSECURE_KEY_ID
# and SPLITSECURE_PRIVATE_KEY, and SPLITSECURE_ENDPOINT outside production.
provider "splitsecure" {}

provider "aws" {
  region = var.aws_region
}

data "splitsecure_vault" "main" {
  name = var.vault_name
}

data "aws_iam_policy" "read_only" {
  name = "ReadOnlyAccess"
}

# The identity provider that signs every SAML assertion.
resource "splitsecure_saml2_identity_provider" "aws" {
  vault_id = data.splitsecure_vault.main.id
  folder   = var.folder
  name     = "aws-saml"

  justification = "Sign in to AWS with SAML"
}

# AWS trusts the identity provider through its metadata.
resource "aws_iam_saml_provider" "splitsecure" {
  name                   = "splitsecure"
  saml_metadata_document = splitsecure_saml2_identity_provider.aws.metadata_xml
}

# The app carries principal tags, so the trust policy allows sts:TagSession.
data "aws_iam_policy_document" "trust" {
  statement {
    actions = ["sts:AssumeRoleWithSAML", "sts:TagSession"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_saml_provider.splitsecure.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "SAML:aud"
      values   = ["https://signin.aws.amazon.com/saml"]
    }
  }
}

resource "aws_iam_role" "ops" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.trust.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "read_only" {
  role       = aws_iam_role.ops.name
  policy_arn = data.aws_iam_policy.read_only.arn
}

resource "splitsecure_connected_app" "aws" {
  issuer_vault_id = data.splitsecure_vault.main.id
  issuer_id       = splitsecure_saml2_identity_provider.aws.id
  template        = "saml2/aws"
  folder          = var.folder
  name            = "aws-${var.role_name}"

  saml2 {
    entity_id = "urn:amazon:webservices"
    acs_url   = "https://signin.aws.amazon.com/saml"
  }

  field {
    name  = "role_arn"
    value = aws_iam_role.ops.arn
  }

  field {
    name  = "saml_provider_arn"
    value = aws_iam_saml_provider.splitsecure.arn
  }

  # The NameID is the requester's email.
  field {
    name  = "name_id_format"
    value = "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress"
  }

  field {
    name      = "requester_email"
    requester = "email"
  }

  name_id {
    parts = ["field:requester_email"]
  }

  # Each sign-in chooses a session length up to the role's maximum.
  field {
    name = "session_duration"
    duration_range {
      min_seconds     = 900
      max_seconds     = aws_iam_role.ops.max_session_duration
      default_seconds = 1800
    }
  }

  field {
    name  = "session_tag"
    key   = "Team"
    value = var.team_tag
  }

  justification = "Let the team sign in to the ${var.role_name} role"
}
