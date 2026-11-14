# The group leaves members unset, so other members added in the
# console stay. Terraform adds and removes only this one.
resource "splitsecure_group" "on_call" {
  name = "On-call"
}

# A service account, by its own address.
data "splitsecure_principal" "deploy_bot" {
  email = var.deploy_bot_address
}

resource "splitsecure_group_member" "deploy_bot" {
  group_s2r = splitsecure_group.on_call.group_s2r
  member    = data.splitsecure_principal.deploy_bot.s2r
}
