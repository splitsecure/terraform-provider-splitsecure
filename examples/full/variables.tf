variable "org_s2r" {
  type        = string
  description = "Org s2r URI hosting the team below. Used by the provider to spawn the proposal-scoped managed enclave on every Create / Delete."
}

variable "team_s2r" {
  type        = string
  description = "Team s2r URI that owns the IdP and SP. Voters on this team approve every Create / Delete proposal."
}

variable "operator_emails" {
  type        = list(string)
  default     = []
  description = "Emails (as shown in the console) of users / service accounts allowed to operate the AWS federation SP."
}
