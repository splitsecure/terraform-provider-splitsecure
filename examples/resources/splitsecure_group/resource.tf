# Groups are named sets of principals used as grant targets. Terraform
# manages locally-sourced groups only: SCIM groups are owned by the
# IdP and the system "Everyone" group is implicit. The members list is
# authoritative — principals added out of band are removed on the next
# apply.
#
# Group mutations require the service account behind the provider to
# hold the org admin role.
#
# Members are referenced by the email shown in the console; the
# splitsecure_principal data source resolves each to its s2r (users and
# service accounts alike).
resource "splitsecure_group" "sre" {
  name = "SRE"
  members = [
    data.splitsecure_principal.alice.s2r,  # a user
    data.splitsecure_principal.ci_bot.s2r, # a service account
  ]
}
