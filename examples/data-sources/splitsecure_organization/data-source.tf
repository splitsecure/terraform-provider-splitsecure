data "splitsecure_organization" "current" {}

data "splitsecure_vault" "platform" {
  name = "Platform"
}

resource "splitsecure_vault_folder" "runbooks" {
  vault_id = data.splitsecure_vault.platform.id
  name     = "runbooks"
}

# Everyone in the org can see the folder.
resource "splitsecure_vault_grant" "everyone_view" {
  vault_id = data.splitsecure_vault.platform.id
  node_id  = splitsecure_vault_folder.runbooks.id
  grantee  = data.splitsecure_organization.current.everyone_group_s2r
  tier     = "view"
}
