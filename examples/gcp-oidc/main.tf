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
# and SPLITSECURE_PRIVATE_KEY, and SPLITSECURE_ENDPOINT outside production.
provider "splitsecure" {}

provider "google" {
  project = var.project_id
}

data "splitsecure_vault" "gcp_access" {
  name = var.vault_name
}

data "google_project" "current" {}

locals {
  pool_name = "projects/${data.google_project.current.number}/locations/global/workloadIdentityPools/${google_iam_workload_identity_pool.splitsecure.workload_identity_pool_id}"

  # The audience every token carries: the full name of the pool provider.
  audience = "https://iam.googleapis.com/${local.pool_name}/providers/${google_iam_workload_identity_pool_provider.splitsecure.workload_identity_pool_provider_id}"
}

# The token exchange and the service account impersonation need these APIs.
resource "google_project_service" "federation" {
  for_each = toset(["iam.googleapis.com", "iamcredentials.googleapis.com", "sts.googleapis.com"])

  service            = each.value
  disable_on_destroy = false
}

# The folder that holds the records. Deleting it moves anything left inside to lost+found.
resource "splitsecure_vault_folder" "gcp" {
  vault_id  = data.splitsecure_vault.gcp_access.id
  name      = var.folder_name
  parent_id = var.parent_folder_id == "" ? null : var.parent_folder_id
}

# The issuer that signs every token. Google Cloud takes an ES256 key.
resource "splitsecure_oidc_issuer" "gcp_federation" {
  vault_id  = data.splitsecure_vault.gcp_access.id
  folder_id = splitsecure_vault_folder.gcp.id
  name      = "Google Cloud federation issuer"
  algs      = ["ES256"]

  justification = "Issue tokens Google Cloud exchanges for service account tokens"
}

resource "google_iam_workload_identity_pool" "splitsecure" {
  workload_identity_pool_id = var.pool_id
  display_name              = "SplitSecure"

  depends_on = [google_project_service.federation]
}

# The pool provider trusts the issuer, takes the audience of its own name, and maps the token subject.
resource "google_iam_workload_identity_pool_provider" "splitsecure" {
  workload_identity_pool_id          = google_iam_workload_identity_pool.splitsecure.workload_identity_pool_id
  workload_identity_pool_provider_id = var.pool_provider_id
  display_name                       = "SplitSecure issuer"

  attribute_mapping = {
    "google.subject" = "assertion.sub"
  }

  oidc {
    issuer_uri        = splitsecure_oidc_issuer.gcp_federation.issuer
    allowed_audiences = ["https://iam.googleapis.com/${local.pool_name}/providers/${var.pool_provider_id}"]
  }
}

# The service account a token is exchanged for.
resource "google_service_account" "federated" {
  account_id   = var.service_account_id
  display_name = "SplitSecure federated access"
}

resource "google_project_iam_member" "federated" {
  project = var.project_id
  role    = var.service_account_role
  member  = google_service_account.federated.member
}

resource "splitsecure_connected_app" "gcp_service_account" {
  issuer_vault_id = data.splitsecure_vault.gcp_access.id
  issuer_id       = splitsecure_oidc_issuer.gcp_federation.id
  template        = "oidc/gcp"
  folder_id       = splitsecure_vault_folder.gcp.id
  name            = "Google Cloud (${var.service_account_id})"

  oidc {
    key_id = one([for k in splitsecure_oidc_issuer.gcp_federation.keys : k.key_id if k.alg == "ES256"])
  }

  field {
    name  = "project_number"
    value = data.google_project.current.number
  }

  field {
    name  = "pool_id"
    value = google_iam_workload_identity_pool.splitsecure.workload_identity_pool_id
  }

  field {
    name  = "provider_id"
    value = google_iam_workload_identity_pool_provider.splitsecure.workload_identity_pool_provider_id
  }

  field {
    name  = "service_account_email"
    value = google_service_account.federated.email
  }

  # Each sign-in chooses how long the service account token lives.
  field {
    name = "access_token_lifetime"
    duration_range {
      min_seconds     = 300
      max_seconds     = 3600
      default_seconds = 3600
    }
  }

  justification = "Let the team act as ${var.service_account_id}"
}

# Only tokens with the subject SplitSecure derived for this app can act as the service account.
resource "google_service_account_iam_member" "token_exchange" {
  service_account_id = google_service_account.federated.name
  role               = "roles/iam.workloadIdentityUser"
  member             = "principal://iam.googleapis.com/${local.pool_name}/subject/${splitsecure_connected_app.gcp_service_account.derived_values["subject"]}"
}

# Optional: let a principal or group use the app.
resource "splitsecure_vault_grant" "app_use" {
  count = var.grantee == "" ? 0 : 1

  vault_id = data.splitsecure_vault.gcp_access.id
  node_id  = splitsecure_connected_app.gcp_service_account.id
  grantee  = var.grantee
  tier     = "use"
}
