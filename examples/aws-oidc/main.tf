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
    tls = {
      source  = "hashicorp/tls"
      version = ">= 4.0"
    }
  }
}

# Reads SPLITSECURE_ORG_S2R, SPLITSECURE_SERVICE_ACCOUNT_S2R, SPLITSECURE_KEY_ID
# and SPLITSECURE_PRIVATE_KEY, and SPLITSECURE_ENDPOINT outside production.
provider "splitsecure" {}

provider "aws" {
  region = var.aws_region
}

data "splitsecure_vault" "aws_access" {
  name = var.vault_name
}

data "aws_caller_identity" "current" {}

data "aws_partition" "current" {}

data "aws_iam_policy" "read_only_access" {
  name = "ReadOnlyAccess"
}

locals {
  # The app names the role before the role exists: its trust policy needs the app's subject.
  role_arn = "arn:${data.aws_partition.current.partition}:iam::${data.aws_caller_identity.current.account_id}:role/${var.role_name}"

  # AWS keys the provider's condition keys by the issuer URL without its scheme.
  issuer_host = trimprefix(splitsecure_oidc_issuer.aws_federation.issuer, "https://")
}

# The folder that holds the records. Deleting it moves anything left inside to lost+found.
resource "splitsecure_vault_folder" "aws" {
  vault_id  = data.splitsecure_vault.aws_access.id
  name      = var.folder_name
  parent_id = var.parent_folder_id == "" ? null : var.parent_folder_id
}

# The issuer that signs every token. AWS takes ES256 and ES384 keys.
resource "splitsecure_oidc_issuer" "aws_federation" {
  vault_id  = data.splitsecure_vault.aws_access.id
  folder_id = splitsecure_vault_folder.aws.id
  name      = "AWS federation issuer"
  algs      = ["ES256"]

  justification = "Issue tokens AWS exchanges for role sessions"
}

data "tls_certificate" "issuer" {
  url = splitsecure_oidc_issuer.aws_federation.issuer
}

resource "aws_iam_openid_connect_provider" "splitsecure" {
  url             = splitsecure_oidc_issuer.aws_federation.issuer
  client_id_list  = ["sts.amazonaws.com"]
  thumbprint_list = [data.tls_certificate.issuer.certificates[0].sha1_fingerprint]
}

resource "splitsecure_connected_app" "aws_session" {
  issuer_vault_id = data.splitsecure_vault.aws_access.id
  issuer_id       = splitsecure_oidc_issuer.aws_federation.id
  template        = "oidc/aws"
  folder_id       = splitsecure_vault_folder.aws.id
  name            = "AWS role session (${var.role_name})"

  oidc {
    key_id = one([for k in splitsecure_oidc_issuer.aws_federation.keys : k.key_id if k.alg == "ES256"])
  }

  field {
    name  = "role_arn"
    value = local.role_arn
  }

  # Each sign-in chooses a session length up to the role's maximum.
  field {
    name = "session_duration"
    duration_range {
      min_seconds     = 900
      max_seconds     = var.max_session_seconds
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

# Every token carries principal tags and the requester's session name as the
# source identity, so the trust policy allows sts:TagSession and
# sts:SetSourceIdentity. The subject is the one the enclave derived for this app.
data "aws_iam_policy_document" "assume_with_token" {
  statement {
    actions = ["sts:AssumeRoleWithWebIdentity", "sts:TagSession", "sts:SetSourceIdentity"]

    principals {
      type        = "Federated"
      identifiers = [aws_iam_openid_connect_provider.splitsecure.arn]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.issuer_host}:aud"
      values   = ["sts.amazonaws.com"]
    }

    condition {
      test     = "StringEquals"
      variable = "${local.issuer_host}:sub"
      values   = [splitsecure_connected_app.aws_session.derived_values["subject"]]
    }
  }
}

resource "aws_iam_role" "session_read_only" {
  name                 = var.role_name
  assume_role_policy   = data.aws_iam_policy_document.assume_with_token.json
  max_session_duration = var.max_session_seconds
}

resource "aws_iam_role_policy_attachment" "session_read_only" {
  role       = aws_iam_role.session_read_only.name
  policy_arn = data.aws_iam_policy.read_only_access.arn
}

# Optional: let a principal or group use the app.
resource "splitsecure_vault_grant" "app_use" {
  count = var.grantee == "" ? 0 : 1

  vault_id = data.splitsecure_vault.aws_access.id
  node_id  = splitsecure_connected_app.aws_session.id
  grantee  = var.grantee
  tier     = "use"
}
