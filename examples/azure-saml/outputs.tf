output "user_principal_name" {
  description = "User principal name of the federated user."
  value       = azuread_user.federated.user_principal_name
}

output "connected_app_id" {
  description = "Record id of the connected app in the vault."
  value       = splitsecure_connected_app.entra_user.id
}
