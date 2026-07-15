terraform {
  required_providers {
    splitsecure = {
      source = "splitsecure/splitsecure"
    }
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.0"
    }
  }
}

provider "splitsecure" {
  org_s2r = var.org_s2r
}

provider "aws" {}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
}

resource "splitsecure_saml2_identity_provider" "main" {
  team_s2r = var.team_s2r

  name        = "aws-${local.account_id}"
  description = "SAML IdP from terraform-provider-splitsecure's example plan."

  justification = "Creating SAML IdP from terraform-provider-splitsecure's example plan."
}

resource "aws_iam_saml_provider" "main" {
  name                   = "splitsecure-${local.account_id}"
  saml_metadata_document = splitsecure_saml2_identity_provider.main.metadata_xml
}

resource "aws_iam_role" "admin" {
  name        = "SplitSecureAdmin-${local.account_id}"
  description = "Admin role from terraform-provider-splitsecure's example plan."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_saml_provider.main.arn }
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

resource "aws_iam_role" "readonly" {
  name        = "SplitSecureReadOnly-${local.account_id}"
  description = "ReadOnly role from terraform-provider-splitsecure's example plan."

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Federated = aws_iam_saml_provider.main.arn }
      Action    = "sts:AssumeRoleWithSAML"
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

resource "splitsecure_saml2_service_provider" "main" {
  team_s2r         = var.team_s2r
  idp_resource_s2r = splitsecure_saml2_identity_provider.main.id

  name                = "aws-${local.account_id}"
  description         = "SAML SP from terraform-provider-splitsecure's example plan."
  notification_policy = "notify_everyone"
  sensitivity         = "critical"
  entity_id           = "urn:amazon:webservices"
  acs_url             = "https://signin.aws.amazon.com/saml"

  justification = "Creating SAML SP from terraform-provider-splitsecure's example plan."

  account {
    kind = "aws"
    aws {
      saml_provider_arn = aws_iam_saml_provider.main.arn
      allowed_role_arns = [
        aws_iam_role.admin.arn,
        aws_iam_role.readonly.arn,
      ]
    }
  }
}

output "aws_account_id" {
  value       = local.account_id
  description = "AWS account ID this federation targets."
}

output "idp_s2r" {
  value       = splitsecure_saml2_identity_provider.main.id
  description = "Resource s2r URI of the SplitSecure IdP."
}

output "sp_s2r" {
  value       = splitsecure_saml2_service_provider.main.id
  description = "Resource s2r URI of the SplitSecure SP."
}

output "idp_sso_url_redirect" {
  value       = splitsecure_saml2_identity_provider.main.sso_url_redirect
  description = "SSO URL (HTTP-Redirect binding) assigned by the backend."
}

output "idp_sso_url_post" {
  value       = splitsecure_saml2_identity_provider.main.sso_url_post
  description = "SSO URL (HTTP-POST binding) assigned by the backend."
}

output "idp_metadata_xml" {
  value       = splitsecure_saml2_identity_provider.main.metadata_xml
  description = "SAML IdP metadata XML rendered from the signing cert, provider_id, and SSO URLs."
}

output "aws_saml_provider_arn" {
  value       = aws_iam_saml_provider.main.arn
  description = "ARN of the AWS-side SAML provider mirror."
}

output "aws_admin_role_arn" {
  value       = aws_iam_role.admin.arn
  description = "ARN of the admin role users assume via SAML."
}

output "aws_readonly_role_arn" {
  value       = aws_iam_role.readonly.arn
  description = "ARN of the readonly role users assume via SAML."
}

# --- Access -------------------------------------------------------
# Terraform-managed permissions on the SP. Without grants, only org
# owners/admins (and the creating service account) can see it.

data "splitsecure_organization" "current" {}

# Resolve each console email to its principal s2r (users and service
# accounts alike), so callers paste emails rather than raw s2rs.
data "splitsecure_principal" "operators" {
  for_each = toset(var.operator_emails)
  email    = each.value
}

resource "splitsecure_group" "operators" {
  name    = "aws-federation-operators-${local.account_id}"
  members = [for p in data.splitsecure_principal.operators : p.s2r]
}

resource "splitsecure_grant" "operators_use" {
  resource_s2r = splitsecure_saml2_service_provider.main.id
  grantee_s2r  = splitsecure_group.operators.group_s2r
  tier         = "use"
}

resource "splitsecure_grant" "org_view" {
  resource_s2r = splitsecure_saml2_service_provider.main.id
  grantee_s2r  = data.splitsecure_organization.current.everyone_group_s2r
  tier         = "view"
}
