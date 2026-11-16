variable "project_id" {
  description = "Id of the Google Cloud project that holds the pool and the service account."
  type        = string
}

variable "vault_name" {
  description = "Name of the SplitSecure vault that holds the issuer and the app."
  type        = string
}

variable "folder_name" {
  description = "Name of the vault folder that holds the records. Terraform creates it."
  type        = string
  default     = "gcp"
}

variable "parent_folder_id" {
  description = "Node id of the folder to create it in. Leave empty for the vault root. The service account needs a grant on that folder."
  type        = string
  default     = ""
}

variable "grantee" {
  description = "Full s2r of a principal or group that gets use access to the app. Leave empty to grant nobody."
  type        = string
  default     = ""
}

variable "pool_id" {
  description = "Id of the workload identity pool Terraform creates. A deleted pool keeps its id for 30 days."
  type        = string
  default     = "splitsecure"

  validation {
    condition     = can(regex("^[a-z0-9-]{4,32}$", var.pool_id)) && !startswith(var.pool_id, "gcp-")
    error_message = "A pool id is 4 to 32 characters of a-z, 0-9 and -, and does not start with gcp-."
  }
}

variable "pool_provider_id" {
  description = "Id of the pool provider Terraform creates."
  type        = string
  default     = "splitsecure-oidc"

  validation {
    condition     = can(regex("^[a-z0-9-]{4,32}$", var.pool_provider_id)) && !startswith(var.pool_provider_id, "gcp-")
    error_message = "A pool provider id is 4 to 32 characters of a-z, 0-9 and -, and does not start with gcp-."
  }
}

variable "service_account_id" {
  description = "Account id of the service account Terraform creates, the part before the @."
  type        = string
  default     = "splitsecure-federated"
}

variable "service_account_role" {
  description = "Project role of the service account."
  type        = string
  default     = "roles/viewer"
}
