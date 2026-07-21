# Resolve an org member by email to the user S2R used as a grant or
# group-member target. Errors if the email matches zero or multiple
# members.
data "splitsecure_org_member" "alice" {
  email = "alice@example.com"
}
