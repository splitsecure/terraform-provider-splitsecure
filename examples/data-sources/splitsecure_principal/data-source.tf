# Resolve an org principal (user or service account) to its s2r by the email
# shown in the console. Use the s2r as a group member or grant grantee.

# A human user.
data "splitsecure_principal" "alice" {
  email = "alice@example.com"
}

# A service account (email is the one displayed in the console).
data "splitsecure_principal" "ci_bot" {
  email = "kQ7...@abc123.serviceaccount.us.splitsecure.com"
}
