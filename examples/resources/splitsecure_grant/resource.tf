# Grants authorize a principal (user, service account, or group) to act
# on one resource at a tier: view < use < edit. PutGrant semantics are
# upsert, so changing tier updates the grant in place; changing the
# resource or grantee replaces it.
#
# Org owners and admins hold the edit tier on every resource implicitly;
# grants matter for plain members.

# Grant a group access to a SAML2 service provider.
resource "splitsecure_grant" "sre_use" {
  resource_s2r = splitsecure_saml2_service_provider.main.id
  grantee_s2r  = data.splitsecure_group.sre.group_s2r
  tier         = "use"
}

# Grant every org member visibility via the system "Everyone" group.
resource "splitsecure_grant" "org_view" {
  resource_s2r = splitsecure_saml2_service_provider.main.id
  grantee_s2r  = data.splitsecure_organization.current.everyone_group_s2r
  tier         = "view"
}
