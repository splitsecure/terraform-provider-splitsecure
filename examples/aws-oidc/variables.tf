variable "aws_region" {
  description = "AWS region for the provider. IAM is global, so any region works."
  type        = string
}

variable "vault_name" {
  description = "Name of the SplitSecure vault that holds the issuer and the app."
  type        = string
}

variable "role_name" {
  description = "Name of the IAM role the app signs in to. The app names it before it exists."
  type        = string
  default     = "SplitSecureOps"
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
