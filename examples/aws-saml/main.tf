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
# and SPLITSECURE_PRIVATE_KEY.
provider "splitsecure" {}

provider "aws" {
  region = var.aws_region
}

data "splitsecure_vault" "aws_access" {
  name = var.vault_name
}

data "aws_iam_policy" "read_only_access" {
  name = "ReadOnlyAccess"
}

# The folder that holds the records. Deleting it moves anything left inside to lost+found.
resource "splitsecure_vault_folder" "aws" {
  vault_id  = data.splitsecure_vault.aws_access.id
  name      = var.folder_name
  parent_id = var.parent_folder_id == "" ? null : var.parent_folder_id
}

# The identity provider that signs every SAML assertion.
resource "splitsecure_saml2_identity_provider" "aws_federation" {
  vault_id  = data.splitsecure_vault.aws_access.id
  folder_id = splitsecure_vault_folder.aws.id
  name      = "AWS console sign-in"

  justification = "Sign in to the AWS console with SAML"
}

# AWS trusts the identity provider through its metadata.
resource "aws_iam_saml_provider" "splitsecure" {
  name                   = "SplitSecure"
  saml_metadata_document = splitsecure_saml2_identity_provider.aws_federation.metadata_xml
}

# The app carries principal tags, so the trust policy allows sts:TagSession.
data "aws_iam_policy_document" "assume_with_saml" {
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

resource "aws_iam_role" "console_read_only" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.assume_with_saml.json
  max_session_duration = 3600
}

resource "aws_iam_role_policy_attachment" "console_read_only" {
  role       = aws_iam_role.console_read_only.name
  policy_arn = data.aws_iam_policy.read_only_access.arn
}

resource "splitsecure_connected_app" "aws_console" {
  issuer_vault_id = data.splitsecure_vault.aws_access.id
  issuer_id       = splitsecure_saml2_identity_provider.aws_federation.id
  template        = "saml2/aws"
  folder_id       = splitsecure_vault_folder.aws.id
  name            = "AWS console (${var.role_name})"

  saml2 {
    entity_id = "urn:amazon:webservices"
    acs_url   = "https://signin.aws.amazon.com/saml"
  }

  field {
    name  = "role_arn"
    value = aws_iam_role.console_read_only.arn
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

  # Each sign-in chooses a session of up to 30 minutes, below the role's 1 hour maximum.
  field {
    name = "session_duration"
    duration_range {
      min_seconds     = 900
      max_seconds     = 1800
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

# Optional: let a principal or group use the app.
resource "splitsecure_vault_grant" "app_use" {
  count = var.grantee == "" ? 0 : 1

  vault_id = data.splitsecure_vault.aws_access.id
  node_id  = splitsecure_connected_app.aws_console.id
  grantee  = var.grantee
  tier     = "use"
}
