data "splitsecure_vault" "platform" {
  name = "Platform"
}

data "splitsecure_group" "sre" {
  name = "SRE"
}

data "splitsecure_organization" "current" {}

resource "splitsecure_vault_folder" "aws" {
  vault_id = data.splitsecure_vault.platform.id
  name     = "aws"
}

# The folder keeps exactly these direct grants, plus the grant of the
# service account Terraform signs in as. Every other direct grant is removed.
resource "splitsecure_vault_node_grants" "aws" {
  vault_id = data.splitsecure_vault.platform.id
  node_id  = splitsecure_vault_folder.aws.id

  grant {
    grantee = data.splitsecure_group.sre.group_s2r
    tier    = "use"
  }

  grant {
    grantee = data.splitsecure_organization.current.everyone_group_s2r
    tier    = "view"
  }
}
