terraform {
  required_version = ">= 1.11"

  required_providers {
    splitsecure = {
      source = "splitsecure/splitsecure"
    }
    azuread = {
      source  = "hashicorp/azuread"
      version = ">= 3.0"
    }
    msgraph = {
      source  = "microsoft/msgraph"
      version = ">= 0.6"
    }
    random = {
      source  = "hashicorp/random"
      version = ">= 3.0"
    }
  }
}

# Reads SPLITSECURE_ORG_S2R, SPLITSECURE_SERVICE_ACCOUNT_S2R, SPLITSECURE_KEY_ID
# and SPLITSECURE_PRIVATE_KEY.
provider "splitsecure" {}

# Both read the tenant and the credentials from the Azure CLI or the ARM_ environment variables.
provider "azuread" {}

# Federates the domain. The azuread provider has no resource for it.
provider "msgraph" {}

data "splitsecure_vault" "azure_access" {
  name = var.vault_name
}

# The verified domains of the tenant.
data "azuread_domains" "verified" {}

# The folder that holds the records. Deleting it moves anything left inside to lost+found.
resource "splitsecure_vault_folder" "azure" {
  vault_id  = data.splitsecure_vault.azure_access.id
  name      = var.folder_name
  parent_id = var.parent_folder_id == "" ? null : var.parent_folder_id
}

# The identity provider that signs every SAML assertion. Entra ID trusts it once the domain is federated.
resource "splitsecure_saml2_identity_provider" "entra_federation" {
  vault_id  = data.splitsecure_vault.azure_access.id
  folder_id = splitsecure_vault_folder.azure.id
  name      = "Entra ID sign-in (${var.domain})"

  justification = "Sign in to Entra ID with SAML for ${var.domain}"
}

# Entra ID finds a federated user by the immutable id in the NameID.
resource "random_uuid" "immutable_id" {}

# Entra ID needs a password to create the user. Federated sign-in does not use it.
resource "random_password" "unused" {
  length  = 32
  special = true
}

resource "azuread_user" "federated" {
  user_principal_name     = "${var.user_name}@${var.domain}"
  display_name            = var.display_name
  mail_nickname           = var.user_name
  onpremises_immutable_id = random_uuid.immutable_id.result
  password                = random_password.unused.result

  lifecycle {
    precondition {
      condition     = contains([for d in data.azuread_domains.verified.domains : d.domain_name], var.domain)
      error_message = "The domain is not a verified domain of the tenant. Add and verify it in Entra ID first."
    }
  }
}

resource "splitsecure_connected_app" "entra_user" {
  issuer_vault_id = data.splitsecure_vault.azure_access.id
  issuer_id       = splitsecure_saml2_identity_provider.entra_federation.id
  template        = "saml2/microsoft-entra-id"
  folder_id       = splitsecure_vault_folder.azure.id
  name            = "Entra ID (${azuread_user.federated.user_principal_name})"

  # The service provider values from Microsoft's federation metadata.
  saml2 {
    entity_id = "urn:federation:MicrosoftOnline"
    acs_url   = "https://login.microsoftonline.com/login.srf"
  }

  # A persistent NameID that holds the user's immutable id.
  field {
    name  = "name_id_format"
    value = "urn:oasis:names:tc:SAML:2.0:nameid-format:persistent"
  }

  field {
    name  = "name_id"
    value = azuread_user.federated.onpremises_immutable_id
  }

  field {
    name  = "user_principal_name"
    value = azuread_user.federated.user_principal_name
  }

  justification = "Let the team sign in to Entra ID as ${azuread_user.federated.user_principal_name}"
}

# Sends every sign-in of the domain to the identity provider. Destroy removes it before the identity provider.
resource "msgraph_resource" "domain_federation" {
  url = "domains/${var.domain}/federationConfiguration"
  body = {
    "@odata.type"                   = "#microsoft.graph.internalDomainFederation"
    displayName                     = "SplitSecure"
    issuerUri                       = splitsecure_saml2_identity_provider.entra_federation.provider_id
    passiveSignInUri                = splitsecure_saml2_identity_provider.entra_federation.sso_url_post
    signingCertificate              = splitsecure_saml2_identity_provider.entra_federation.signing_certificate_der
    preferredAuthenticationProtocol = "saml"
    federatedIdpMfaBehavior         = "acceptIfMfaDoneByFederatedIdp"
  }

  # The user's precondition refuses a domain that is not verified.
  depends_on = [azuread_user.federated]
}

# Optional: let a principal or group use the app.
resource "splitsecure_vault_grant" "app_use" {
  count = var.grantee == "" ? 0 : 1

  vault_id = data.splitsecure_vault.azure_access.id
  node_id  = splitsecure_connected_app.entra_user.id
  grantee  = var.grantee
  tier     = "use"
}
