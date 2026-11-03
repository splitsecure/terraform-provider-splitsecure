data "splitsecure_vault" "platform" {
  label = "platform"
}

resource "splitsecure_saml2_identity_provider" "aws_console" {
  vault_id = data.splitsecure_vault.platform.id

  name        = "platform-engineering/aws-123456789012"
  description = "SAML IdP fronting AWS account 123456789012."

  # Shown to approvers when the create needs approval. Write-only.
  justification = "Federate the AWS console for platform engineering"

  # Hold the create open for approval before Terraform starts polling.
  wait = "30s"
}

resource "aws_iam_saml_provider" "splitsecure" {
  name                   = "splitsecure"
  saml_metadata_document = splitsecure_saml2_identity_provider.aws_console.metadata_xml
}
