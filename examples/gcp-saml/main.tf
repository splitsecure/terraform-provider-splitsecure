terraform {
  required_version = ">= 1.11"

  required_providers {
    splitsecure = {
      source = "splitsecure/splitsecure"
    }
    google = {
      source  = "hashicorp/google"
      version = ">= 6.0"
    }
  }
}

# Reads SPLITSECURE_ORG_S2R, SPLITSECURE_SERVICE_ACCOUNT_S2R, SPLITSECURE_KEY_ID
# and SPLITSECURE_PRIVATE_KEY.
provider "splitsecure" {}

provider "google" {
  project = var.project_id
}

data "splitsecure_vault" "gcp_access" {
  name = var.vault_name
}

locals {
  pool_path = "locations/global/workforcePools/${google_iam_workforce_pool.splitsecure.workforce_pool_id}"

  # Google Cloud names the service provider by the pool and the provider.
  provider_path = "${local.pool_path}/providers/${google_iam_workforce_pool_provider.splitsecure.provider_id}"
}

# The folder that holds the records. Deleting it moves anything left inside to lost+found.
resource "splitsecure_vault_folder" "gcp" {
  vault_id  = data.splitsecure_vault.gcp_access.id
  name      = var.folder_name
  parent_id = var.parent_folder_id == "" ? null : var.parent_folder_id
}

# The identity provider that signs every SAML assertion.
resource "splitsecure_saml2_identity_provider" "gcp_federation" {
  vault_id  = data.splitsecure_vault.gcp_access.id
  folder_id = splitsecure_vault_folder.gcp.id
  name      = "Google Cloud console sign-in"

  justification = "Sign in to the Google Cloud console with SAML"
}

# A workforce pool of the organization, for people outside Google's own directory.
resource "google_iam_workforce_pool" "splitsecure" {
  parent            = "organizations/${var.organization_id}"
  location          = "global"
  workforce_pool_id = var.pool_id
  display_name      = "SplitSecure"
  session_duration  = "1800s"
}

# The pool trusts the identity provider through its metadata, and takes the NameID as the user.
resource "google_iam_workforce_pool_provider" "splitsecure" {
  workforce_pool_id = google_iam_workforce_pool.splitsecure.workforce_pool_id
  location          = google_iam_workforce_pool.splitsecure.location
  provider_id       = var.pool_provider_id
  display_name      = "SplitSecure"

  attribute_mapping = {
    "google.subject" = "assertion.subject"
  }

  saml {
    idp_metadata_xml = splitsecure_saml2_identity_provider.gcp_federation.metadata_xml
  }
}

# Each user gets the role on the project. The subject is the NameID: the requester's email.
resource "google_project_iam_member" "federated_user" {
  for_each = toset(var.user_emails)

  project = var.project_id
  role    = var.user_role
  member  = "principal://iam.googleapis.com/${local.pool_path}/subject/${each.value}"
}

resource "splitsecure_connected_app" "gcp_console" {
  issuer_vault_id = data.splitsecure_vault.gcp_access.id
  issuer_id       = splitsecure_saml2_identity_provider.gcp_federation.id
  template        = "saml2/gcp"
  folder_id       = splitsecure_vault_folder.gcp.id
  name            = "Google Cloud console (${var.pool_id})"

  saml2 {
    entity_id = "https://iam.googleapis.com/${local.provider_path}"
    acs_url   = "https://auth.cloud.google/signin-callback/${local.provider_path}"
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

  justification = "Let the team sign in to the Google Cloud console"
}

# Optional: let a principal or group use the app.
resource "splitsecure_vault_grant" "app_use" {
  count = var.grantee == "" ? 0 : 1

  vault_id = data.splitsecure_vault.gcp_access.id
  node_id  = splitsecure_connected_app.gcp_console.id
  grantee  = var.grantee
  tier     = "use"
}
