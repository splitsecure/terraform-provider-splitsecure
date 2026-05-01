terraform {
  required_providers {
    splitsecure = {
      source = "splitsecure/splitsecure"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
    time = {
      source  = "hashicorp/time"
      version = "~> 0.11"
    }
  }
}

provider "splitsecure" {
  org_s2r = var.org_s2r
}

provider "aws" {
  region = "us-east-1"
}

variable "org_s2r" {
  type        = string
  description = "Org s2r URI hosting the teams below. Used by the provider to spawn the proposal-scoped managed enclave on every Create / Delete."
}

variable "engineering_team_s2r" {
  type        = string
  description = "Team s2r URI for the Engineering team. Voters here approve every Engineering Create / Delete proposal."
}

variable "support_team_s2r" {
  type        = string
  description = "Team s2r URI for the Technical Support team. Voters here approve every Technical Support Create / Delete proposal."
}

# Resolve the AWS account the federation lands in.
data "aws_caller_identity" "current" {}

# Captured the first time `terraform apply` runs and frozen in state
# from then on.
resource "time_static" "rollout" {}

locals {
  account_id   = data.aws_caller_identity.current.account_id
  rollout_date = formatdate("YYYY-MM-DD", time_static.rollout.rfc3339)
}

# IdPs are per-team: the threshold-signed cert binds to the team's
# voters, so each team gets its own SAML identity. Engineering and
# Technical Support each mint their own.

resource "splitsecure_saml2_identity_provider" "engineering" {
  team_s2r = var.engineering_team_s2r

  name        = "engineering/aws-${local.account_id}"
  description = "Engineering SAML IdP for AWS account ${local.account_id}."

  justification = "Stand up the Engineering IdP for federation into AWS account ${local.account_id}."
}

resource "splitsecure_saml2_identity_provider" "support" {
  team_s2r = var.support_team_s2r

  name        = "support/aws-${local.account_id}"
  description = "Technical Support SAML IdP for AWS account ${local.account_id}."

  justification = "Stand up the Technical Support IdP for federation into AWS account ${local.account_id}."
}

# AWS-side mirrors of each IdP. Distinct ARNs so role trust policies
# can grant access per-team.
resource "aws_iam_saml_provider" "engineering" {
  name                   = "splitsecure-engineering-${local.account_id}"
  saml_metadata_document = splitsecure_saml2_identity_provider.engineering.metadata_xml
}

resource "aws_iam_saml_provider" "support" {
  name                   = "splitsecure-support-${local.account_id}"
  saml_metadata_document = splitsecure_saml2_identity_provider.support.metadata_xml
}

# Admin role: only Engineering can assume it. Trust policy lists just
# the Engineering SAML provider.
resource "aws_iam_role" "admin" {
  name        = "SplitSecureAdmin-${local.account_id}"
  description = "Admin role assumed via SplitSecure SAML federation by the Engineering team."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_saml_provider.engineering.arn }
      Action    = "sts:AssumeRoleWithSAML"
      Condition = {
        StringEquals = { "SAML:aud" = "https://signin.aws.amazon.com/saml" }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "admin" {
  role       = aws_iam_role.admin.name
  policy_arn = "arn:aws:iam::aws:policy/AdministratorAccess"
}

# ReadOnly role: shared between Engineering and Technical
# Support. Trust policy lists both SAML providers; ReadOnlyAccess
# attached so it's safe for either team.
resource "aws_iam_role" "readonly" {
  name        = "SplitSecureReadOnly-${local.account_id}"
  description = "Read-only readonly role assumed via SplitSecure SAML federation by Engineering or Technical Support."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Principal = {
        Federated = [
          aws_iam_saml_provider.engineering.arn,
          aws_iam_saml_provider.support.arn,
        ]
      }
      Action = "sts:AssumeRoleWithSAML"
      Condition = {
        StringEquals = { "SAML:aud" = "https://signin.aws.amazon.com/saml" }
      }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "readonly" {
  role       = aws_iam_role.readonly.name
  policy_arn = "arn:aws:iam::aws:policy/ReadOnlyAccess"
}

# Engineering admin SP. sensitivity = "critical" — voters see the
# highest classification on every proposal here.
resource "splitsecure_saml2_service_provider" "engineering_admin" {
  team_s2r         = var.engineering_team_s2r
  idp_resource_s2r = splitsecure_saml2_identity_provider.engineering.id

  name                = "engineering/aws-${local.account_id}-admin"
  description         = "Engineering admin federation into AWS account ${local.account_id}."
  notification_policy = "notify_everyone"
  sensitivity         = "critical"
  entity_id           = "urn:amazon:webservices"
  acs_url             = "https://signin.aws.amazon.com/saml"

  justification = "Engineering federation to assume ${aws_iam_role.admin.name} in AWS account ${local.account_id}."

  account {
    kind = "aws"
    aws {
      saml_provider_arn = aws_iam_saml_provider.engineering.arn
      allowed_role_arns = [aws_iam_role.admin.arn]
    }
  }
}

# Engineering readonly SP. sensitivity = "low" mirrors the
# read-only blast radius.
resource "splitsecure_saml2_service_provider" "engineering_readonly" {
  team_s2r         = var.engineering_team_s2r
  idp_resource_s2r = splitsecure_saml2_identity_provider.engineering.id

  name                = "engineering/aws-${local.account_id}-readonly"
  description         = "Engineering read-only federation into AWS account ${local.account_id}."
  notification_policy = "notify_everyone"
  sensitivity         = "low"
  entity_id           = "urn:amazon:webservices"
  acs_url             = "https://signin.aws.amazon.com/saml"

  justification = "Engineering federation to assume ${aws_iam_role.readonly.name} (AWS managed ReadOnlyAccess) in AWS account ${local.account_id}."

  account {
    kind = "aws"
    aws {
      saml_provider_arn = aws_iam_saml_provider.engineering.arn
      allowed_role_arns = [aws_iam_role.readonly.arn]
    }
  }
}

# Technical Support readonly SP. Bound to the Support IdP but
# allowed_role_arns points at the same shared readonly role.
resource "splitsecure_saml2_service_provider" "support_readonly" {
  team_s2r         = var.support_team_s2r
  idp_resource_s2r = splitsecure_saml2_identity_provider.support.id

  name                = "support/aws-${local.account_id}-readonly"
  description         = "Technical Support read-only federation into AWS account ${local.account_id}."
  notification_policy = "notify_everyone"
  sensitivity         = "low"
  entity_id           = "urn:amazon:webservices"
  acs_url             = "https://signin.aws.amazon.com/saml"

  justification = "Technical Support federation to assume ${aws_iam_role.readonly.name} (AWS managed ReadOnlyAccess) in AWS account ${local.account_id}."

  account {
    kind = "aws"
    aws {
      saml_provider_arn = aws_iam_saml_provider.support.arn
      allowed_role_arns = [aws_iam_role.readonly.arn]
    }
  }
}

output "aws_account_id" {
  value       = local.account_id
  description = "AWS account this federation targets."
}

output "rollout_date" {
  value       = local.rollout_date
  description = "Date the federation was first provisioned."
}

output "engineering_idp_s2r" {
  value       = splitsecure_saml2_identity_provider.engineering.id
  description = "Resource s2r URI for the Engineering IdP."
}

output "support_idp_s2r" {
  value       = splitsecure_saml2_identity_provider.support.id
  description = "Resource s2r URI for the Technical Support IdP."
}

output "engineering_admin_sp_s2r" {
  value       = splitsecure_saml2_service_provider.engineering_admin.id
  description = "Resource s2r URI for the Engineering admin SP (sensitivity = critical)."
}

output "engineering_readonly_sp_s2r" {
  value       = splitsecure_saml2_service_provider.engineering_readonly.id
  description = "Resource s2r URI for the Engineering readonly SP (sensitivity = low)."
}

output "support_readonly_sp_s2r" {
  value       = splitsecure_saml2_service_provider.support_readonly.id
  description = "Resource s2r URI for the Technical Support readonly SP (sensitivity = low)."
}

output "admin_role_arn" {
  value       = aws_iam_role.admin.arn
  description = "ARN of the admin role (Engineering only)."
}

output "readonly_role_arn" {
  value       = aws_iam_role.readonly.arn
  description = "ARN of the read-only role (Engineering + Technical Support)."
}
