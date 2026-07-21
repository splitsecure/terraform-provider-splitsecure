# The provider-configured org. everyone_group_s2r is the grantee for
# org-wide grants; the "Everyone" group is a system group and is not
# returned by group listings.
data "splitsecure_organization" "current" {}
