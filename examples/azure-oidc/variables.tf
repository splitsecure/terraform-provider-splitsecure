variable "vault_name" {
  description = "Name of the SplitSecure vault that holds the issuer and the app."
  type        = string
}

variable "folder_name" {
  description = "Name of the vault folder that holds the records. Terraform creates it."
  type        = string
  default     = "azure"
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

variable "application_name" {
  description = "Display name of the Entra ID application Terraform creates."
  type        = string
  default     = "SplitSecure federated access"
}
