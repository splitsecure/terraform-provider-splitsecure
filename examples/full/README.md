# Full example

End-to-end smoke test for the `splitsecure/splitsecure` Terraform provider
against a real backend. Stands up a SAML IdP on a SplitSecure team, mirrors
it on AWS as an `aws_iam_saml_provider`, creates admin and readonly IAM
roles, and binds a single SP allowing federation into both roles.

## Prerequisites

- Terraform 1.6+
- AWS credentials in the active shell
- A SplitSecure service-account API key with permission to propose against
  `team_s2r`

## Setup

AWS credentials must be configured globally in the shell running the
commands (any standard chain works: `AWS_PROFILE`, `AWS_ACCESS_KEY_ID`/
`AWS_SECRET_ACCESS_KEY`, SSO, IAM role on the instance, etc.). Verify with
`aws sts get-caller-identity` before running terraform.

```bash
cp terraform.tfvars.example terraform.tfvars
# edit terraform.tfvars: set org_s2r and team_s2r
export SPLITSECURE_BEARER_TOKEN=s2ak_...
```

## Usage

```bash
make init       # pull the splitsecure + aws providers from the registry
make plan
make apply      # creates 1 IdP + 1 SP (both gated by team voters)
make destroy
make clean      # nuke .terraform, lock file, tfstate
```

`make apply` produces two proposals on the SplitSecure side (IdP create, SP
create) that must be approved by the team before terraform returns. The SP
sensitivity is `critical` because admin federation is in scope.

## What gets created

| Resource                              | Name pattern                                        |
|---------------------------------------|-----------------------------------------------------|
| `splitsecure_saml2_identity_provider` | `aws-<account-id>`                                  |
| `aws_iam_saml_provider`               | `splitsecure-<account-id>`                          |
| `aws_iam_role` (admin)                | `SplitSecureAdmin-<account-id>` + AdministratorAccess |
| `aws_iam_role` (readonly)             | `SplitSecureReadOnly-<account-id>` + ReadOnlyAccess |
| `splitsecure_saml2_service_provider`  | `aws-<account-id>` (allows both roles)              |
