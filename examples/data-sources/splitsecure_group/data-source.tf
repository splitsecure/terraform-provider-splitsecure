# Look up an existing group (e.g. SCIM-synced) by name. Names are not
# unique server-side; the lookup errors on zero or multiple matches.
# The system "Everyone" group is not listed — use the
# splitsecure_organization data source for it.
data "splitsecure_group" "sre" {
  name = "SRE"
}
