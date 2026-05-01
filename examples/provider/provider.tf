terraform {
  required_providers {
    splitsecure = {
      source = "splitsecure/splitsecure"
    }
  }
}

# bearer_token is read from SPLITSECURE_BEARER_TOKEN by default
# (it's the only secret). org_s2r is non-sensitive deployment config
# and is set in HCL.
provider "splitsecure" {
  org_s2r = "s2r:<deployment>:org:<org_id>"
}
