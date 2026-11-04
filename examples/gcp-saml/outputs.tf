output "sign_in_url" {
  description = "Google Cloud sign-in page of the pool provider. It sends the user to SplitSecure."
  value       = "https://auth.cloud.google/signin/${local.provider_path}?continueUrl=https://console.cloud.google/"
}

output "connected_app_id" {
  description = "Record id of the connected app in the vault."
  value       = splitsecure_connected_app.gcp_console.id
}
