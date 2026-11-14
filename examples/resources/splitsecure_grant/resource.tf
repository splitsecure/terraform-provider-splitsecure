# Grants a tier on an org resource: view < use < edit. Changing the
# tier updates the grant in place. For vault folders and records, use
# splitsecure_vault_grant instead.
data "splitsecure_group" "sre" {
  name = "SRE"
}

resource "splitsecure_grant" "sre_use" {
  resource_s2r = var.resource_s2r
  grantee_s2r  = data.splitsecure_group.sre.group_s2r
  tier         = "use"
}
