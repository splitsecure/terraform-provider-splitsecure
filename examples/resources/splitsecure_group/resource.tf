# Groups are named sets of principals used as grant targets. Terraform
# manages locally-sourced groups only: SCIM groups are owned by the
# IdP and the system "Everyone" group is implicit. The members list is
# authoritative — principals added out of band are removed on the next
# apply.
#
# Group mutations require the service account behind the provider to
# hold the org admin role.
resource "splitsecure_group" "sre" {
  name = "SRE"
  members = [
    data.splitsecure_org_member.alice.user_s2r,
    "s2r:us:sa:2qX9mK4pLw8vN3rT",
  ]
}
