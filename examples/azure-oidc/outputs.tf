output "tenant_id" {
  description = "Id of the Entra ID tenant."
  value       = data.azuread_client_config.current.tenant_id
}

output "client_id" {
  description = "Client id of the application a token signs in as."
  value       = azuread_application.federated.client_id
}

output "service_principal_object_id" {
  description = "Object id of the service principal, the identity to grant Azure roles to."
  value       = azuread_service_principal.federated.object_id
}

output "connected_app_id" {
  description = "Record id of the connected app in the vault."
  value       = splitsecure_connected_app.entra_application.id
}
