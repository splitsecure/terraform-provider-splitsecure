# Resolve a group by its stable group_s2r, exposing its current name and
# source (e.g. to assert its source before granting on it). A group's
# name is mutable and not unique server-side, so group_s2r is the only
# lookup key. To use a group as a grant grantee you can also reference
# its s2r directly, without this data source.
data "splitsecure_group" "sre" {
  group_s2r = "s2r:us:group:01HX.../01HY..."
}
