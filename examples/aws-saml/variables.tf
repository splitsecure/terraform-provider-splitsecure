variable "aws_region" {
  description = "AWS region for the provider. IAM is global, so any region works."
  type        = string
}

variable "vault_name" {
  description = "Name of the SplitSecure vault that holds the identity provider and the app."
  type        = string
}

variable "folder" {
  description = "Folder path from the vault root for the identity provider and the app. Missing folders are created under the deepest folder of the path that already exists, so the service account needs a grant on that folder, or on the vault root when none exists."
  type        = list(string)
  default     = ["aws"]
}

variable "role_name" {
  description = "Name of the IAM role the app signs in to."
  type        = string
  default     = "SplitSecureOps"
}

variable "team_tag" {
  description = "Value of the Team session tag every sign-in carries."
  type        = string
  default     = "platform"
}
