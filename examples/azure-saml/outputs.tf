output "user_principal_name" {
  description = "User principal name of the federated user."
  value       = azuread_user.federated.user_principal_name
}

output "connected_app_id" {
  description = "Record id of the connected app in the vault."
  value       = splitsecure_connected_app.entra_user.id
}

# The azuread provider cannot federate a domain. Run this once in PowerShell, with the Microsoft Graph module.
output "federation_command" {
  description = "PowerShell that federates the domain with the identity provider."
  value       = <<-EOT
    Connect-MgGraph -Scopes "Domain.ReadWrite.All"
    New-MgDomainFederationConfiguration `
      -DomainId "${var.domain}" `
      -IssuerUri "${splitsecure_saml2_identity_provider.entra_domain.provider_id}" `
      -PassiveSignInUri "${splitsecure_saml2_identity_provider.entra_domain.sso_url_post}" `
      -SignOutUri "" `
      -SigningCertificate "${splitsecure_saml2_identity_provider.entra_domain.signing_certificate_der}" `
      -PreferredAuthenticationProtocol "saml" `
      -FederatedIdpMfaBehavior "acceptIfMfaDoneByFederatedIdp" `
      -DisplayName "SplitSecure"
  EOT
}
