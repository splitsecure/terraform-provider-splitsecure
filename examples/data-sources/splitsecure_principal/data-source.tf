data "splitsecure_principal" "alice" {
  email = "alice@example.com"
}

# A service account has its own address, as the console shows it:
# <name>@<org id>.us.s2
data "splitsecure_principal" "deploy_bot" {
  email = var.deploy_bot_address
}

data "splitsecure_group" "sre" {
  name = "SRE"
}

resource "splitsecure_group_member" "deploy_bot" {
  group_s2r = data.splitsecure_group.sre.group_s2r
  member    = data.splitsecure_principal.deploy_bot.s2r
}
