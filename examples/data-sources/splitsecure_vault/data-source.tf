# Resolve a vault by its name in the provider's org. The lookup errors
# when no vault, or more than one vault, has the name.
data "splitsecure_vault" "platform" {
  name = "platform"
}

# Search another org.
data "splitsecure_vault" "other" {
  name    = "platform"
  org_s2r = "s2r:us:org:..."
}
