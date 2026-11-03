# Resolve a vault by its label in the provider's org. The lookup errors
# when no vault, or more than one vault, has the label.
data "splitsecure_vault" "platform" {
  label = "platform"
}

# Search another org.
data "splitsecure_vault" "other" {
  label   = "platform"
  org_s2r = "s2r:us:org:..."
}
