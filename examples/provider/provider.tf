terraform {
  required_providers {
    splitsecure = {
      source = "splitsecure/splitsecure"
    }
  }
}

# The service account, key id and private key are read from
# SPLITSECURE_SERVICE_ACCOUNT_S2R, SPLITSECURE_KEY_ID and
# SPLITSECURE_PRIVATE_KEY by default. org_s2r is non-sensitive
# deployment config and is set in HCL.
provider "splitsecure" {
  org_s2r = "s2r:us:org:..."
}
