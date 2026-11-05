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
  }
}

# Reads SPLITSECURE_ORG_S2R, SPLITSECURE_SERVICE_ACCOUNT_S2R, SPLITSECURE_KEY_ID
# and SPLITSECURE_PRIVATE_KEY, and SPLITSECURE_ENDPOINT outside production.
provider "splitsecure" {}

# Reads the tenant and the credentials from the Azure CLI or the ARM_ environment variables.
provider "azuread" {}

data "splitsecure_vault" "azure_access" {
  name = var.vault_name
}

data "azuread_client_config" "current" {}

# The folder that holds the records. Deleting it moves anything left inside to lost+found.
resource "splitsecure_vault_folder" "azure" {
  vault_id  = data.splitsecure_vault.azure_access.id
  name      = var.folder_name
  parent_id = var.parent_folder_id == "" ? null : var.parent_folder_id
}

# The issuer that signs every token. Entra ID takes an RS256 key only.
resource "splitsecure_oidc_issuer" "entra_federation" {
  vault_id  = data.splitsecure_vault.azure_access.id
  folder_id = splitsecure_vault_folder.azure.id
  name      = "Entra ID federation issuer"
  algs      = ["RS256"]

  justification = "Issue tokens Entra ID exchanges for application tokens"
}

# The application a token signs in as, and its service principal in the tenant.
resource "azuread_application" "federated" {
  display_name = var.application_name
}

resource "azuread_service_principal" "federated" {
  client_id = azuread_application.federated.client_id
}

resource "splitsecure_connected_app" "entra_application" {
  issuer_vault_id = data.splitsecure_vault.azure_access.id
  issuer_id       = splitsecure_oidc_issuer.entra_federation.id
  template        = "oidc/azure"
  folder_id       = splitsecure_vault_folder.azure.id
  name            = "Entra ID (${var.application_name})"

  oidc {
    key_id = one([for k in splitsecure_oidc_issuer.entra_federation.keys : k.key_id if k.alg == "RS256"])
  }

  field {
    name  = "tenant_id"
    value = data.azuread_client_config.current.tenant_id
  }

  field {
    name  = "client_id"
    value = azuread_application.federated.client_id
  }

  # Each sign-in chooses how long the token lives.
  field {
    name = "lifetime"
    duration_range {
      min_seconds     = 300
      max_seconds     = 1800
      default_seconds = 600
    }
  }

  justification = "Let the team sign in as ${var.application_name}"
}

# Entra ID accepts a token whose issuer, subject and audience match this credential.
resource "azuread_application_federated_identity_credential" "splitsecure" {
  application_id = azuread_application.federated.id
  display_name   = "splitsecure"
  issuer         = splitsecure_oidc_issuer.entra_federation.issuer
  subject        = splitsecure_connected_app.entra_application.derived_values["subject"]
  audiences      = ["api://AzureADTokenExchange"]
}

# Optional: let a principal or group use the app.
resource "splitsecure_vault_grant" "app_use" {
  count = var.grantee == "" ? 0 : 1

  vault_id = data.splitsecure_vault.azure_access.id
  node_id  = splitsecure_connected_app.entra_application.id
  grantee  = var.grantee
  tier     = "use"
}
