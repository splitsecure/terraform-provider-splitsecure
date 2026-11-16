output "service_account_email" {
  description = "Email of the service account a token is exchanged for."
  value       = google_service_account.federated.email
}

output "audience" {
  description = "Audience of every token: the full name of the pool provider."
  value       = local.audience
}

output "connected_app_id" {
  description = "Record id of the connected app in the vault."
  value       = splitsecure_connected_app.gcp_service_account.id
}
