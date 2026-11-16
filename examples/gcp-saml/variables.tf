variable "organization_id" {
  description = "Numeric id of the Google Cloud organization that holds the workforce pool."
  type        = string
}

variable "project_id" {
  description = "Id of the Google Cloud project the users get a role on."
  type        = string
}

variable "vault_name" {
  description = "Name of the SplitSecure vault that holds the identity provider and the app."
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
  description = "Id of the workforce pool Terraform creates. It is unique across all of Google Cloud, and a deleted pool keeps its id for 30 days."
  type        = string

  validation {
    condition     = can(regex("^[a-z0-9-]{6,63}$", var.pool_id)) && !startswith(var.pool_id, "gcp-")
    error_message = "A workforce pool id is 6 to 63 characters of a-z, 0-9 and -, and does not start with gcp-."
  }
}

variable "pool_provider_id" {
  description = "Id of the pool provider Terraform creates."
  type        = string
  default     = "splitsecure-saml"

  validation {
    condition     = can(regex("^[a-z0-9-]{4,32}$", var.pool_provider_id)) && !startswith(var.pool_provider_id, "gcp-")
    error_message = "A pool provider id is 4 to 32 characters of a-z, 0-9 and -, and does not start with gcp-."
  }
}

variable "user_emails" {
  description = "SplitSecure emails of the users who get the role. Each sign-in sends the requester's email as the user."
  type        = list(string)
  default     = []
}

variable "user_role" {
  description = "Project role of the users."
  type        = string
  default     = "roles/viewer"
}
