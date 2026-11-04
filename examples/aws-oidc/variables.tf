variable "aws_region" {
  description = "AWS region for the provider. IAM is global, so any region works."
  type        = string
}

variable "vault_name" {
  description = "Name of the SplitSecure vault that holds the issuer and the app."
  type        = string
}

variable "folder_name" {
  description = "Name of the vault folder that holds the records. Terraform creates it."
  type        = string
  default     = "aws"
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

variable "role_name" {
  description = "Name of the IAM role the app signs in to. The app names it before it exists."
  type        = string
  default     = "SplitSecureSessionReadOnly"
}

variable "max_session_seconds" {
  description = "Longest role session a sign-in may choose, from 3600 to 43200 seconds."
  type        = number
  default     = 3600

  validation {
    condition     = var.max_session_seconds >= 3600 && var.max_session_seconds <= 43200
    error_message = "AWS allows a role session of 3600 to 43200 seconds."
  }
}

variable "team_tag" {
  description = "Value of the Team session tag every sign-in carries."
  type        = string
  default     = "platform"
}
