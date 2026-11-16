output "role_arn" {
  description = "ARN of the IAM role the app signs in to."
  value       = aws_iam_role.console_read_only.arn
}

output "connected_app_id" {
  description = "Record id of the connected app in the vault."
  value       = splitsecure_connected_app.aws_console.id
}
