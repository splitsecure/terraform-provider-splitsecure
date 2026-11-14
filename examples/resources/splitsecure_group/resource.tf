data "splitsecure_principal" "alice" {
  email = "alice@example.com"
}

# A service account, by its own address.
data "splitsecure_principal" "deploy_bot" {
  email = var.deploy_bot_address
}

# Terraform owns the member set: a member not listed here is removed.
resource "splitsecure_group" "platform" {
  name = "Platform"
  members = [
    data.splitsecure_principal.alice.s2r,
    data.splitsecure_principal.deploy_bot.s2r,
  ]
}

# Members are managed elsewhere, for example in the console.
resource "splitsecure_group" "on_call" {
  name = "On-call"
}
