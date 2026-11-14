data "splitsecure_org_member" "alice" {
  email = "alice@example.com"
}

output "alice_s2r" {
  value = data.splitsecure_org_member.alice.user_s2r
}
